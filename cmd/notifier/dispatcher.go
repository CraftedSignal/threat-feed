package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// dispatchConcurrency caps simultaneous outbound deliveries (SMTP + webhook
// fan-out). Anything higher and we risk swamping the SMTP relay or running
// past Cloud Run's request budget.
const dispatchConcurrency = 10

// dispatcher fans new briefs out to matching subscriptions.
type dispatcher struct {
	store  *firestoreStore
	mailer mailer
	logger *slog.Logger
}

// Dispatch evaluates each new brief against every verified subscription
// and sends matches via the appropriate channel. Deliveries run in
// bounded parallel; errors per delivery are logged but don't fail the
// batch. last_sent is only updated for subs that actually had ≥1
// successful delivery.
func (d *dispatcher) Dispatch(ctx context.Context, briefs []Brief, serviceURL string) (sent int, failed int) {
	now := time.Now().UTC()

	var sentN, failedN atomic.Int64
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(dispatchConcurrency)

	// First pass: collect (sub, brief) pairs into a channel and stream
	// out via the errgroup. The Firestore iterator runs in one
	// goroutine; workers pull from the work queue.
	type job struct {
		sub   Subscription
		brief Brief
	}
	jobs := make(chan job, dispatchConcurrency*2)

	// Track per-sub success so we only update last_sent when something
	// landed. Map needs a mutex since workers may touch the same sub.
	var matchedMu sync.Mutex
	matched := make(map[string]bool)

	g.Go(func() error {
		defer close(jobs)
		return d.store.ForEachVerified(gctx, func(sub Subscription) error {
			for _, b := range briefs {
				if !sub.Filter.Matches(b) {
					continue
				}
				// Update dispatches reach only subscribers who explicitly
				// opted in. A new-brief dispatch ignores the toggle.
				if b.IsUpdate && !sub.Filter.IncludeUpdates {
					continue
				}
				select {
				case jobs <- job{sub: sub, brief: b}:
				case <-gctx.Done():
					return gctx.Err()
				}
			}
			return nil
		})
	})

	// Worker pool. errgroup.SetLimit gives us bounded concurrency.
	for j := range jobs {
		j := j // capture
		g.Go(func() error {
			if err := d.deliver(j.sub, j.brief, serviceURL); err != nil {
				d.logger.Error("delivery failed",
					"sub_id", j.sub.ID,
					"channel", j.sub.Channel,
					"brief", j.brief.Slug,
					"err", err)
				failedN.Add(1)
				return nil // don't abort other deliveries
			}
			sentN.Add(1)
			matchedMu.Lock()
			matched[j.sub.ID] = true
			matchedMu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		d.logger.Error("dispatch iteration failed", "err", err)
	}

	// Update last_sent only for subs with ≥1 successful delivery.
	for subID := range matched {
		_ = d.store.MarkSent(ctx, subID, now)
	}

	return int(sentN.Load()), int(failedN.Load())
}

func (d *dispatcher) deliver(sub Subscription, b Brief, serviceURL string) error {
	switch sub.Channel {
	case ChannelEmail:
		return d.mailer.Send(sub.Email, emailSubject(b), emailBody(b, serviceURL, sub.UnsubscribeToken))
	case ChannelSlack:
		return SendSlack(sub.WebhookURL, b)
	case ChannelTeams:
		return SendTeams(sub.WebhookURL, b)
	default:
		return fmt.Errorf("unknown channel: %q", sub.Channel)
	}
}

func emailSubject(b Brief) string {
	if b.IsUpdate {
		// Updates carry their own marker so an inbox-rule on "[UPDATE]"
		// works the way subscribers expect. Severity stays in the suffix
		// so the recipient can still see how serious the change is.
		return "[UPDATE] " + b.Title + " — " + strings.ToUpper(b.Severity)
	}
	prefix := "[" + strings.ToUpper(b.Severity) + "]"
	if b.Type != "" {
		prefix += " " + cases.Title(language.English).String(b.Type)
	}
	return prefix + ": " + b.Title
}

func emailBody(b Brief, serviceURL, unsubToken string) string {
	var sb strings.Builder
	if b.IsUpdate && b.UpdateSummary != "" {
		sb.WriteString("Update: ")
		sb.WriteString(b.UpdateSummary)
		sb.WriteString("\n\n")
	}
	sb.WriteString(b.Title)
	sb.WriteString("\n\n")
	sb.WriteString(b.Description)
	sb.WriteString("\n\n")
	sb.WriteString("Type: ")
	sb.WriteString(b.Type)
	sb.WriteString("\nSeverity: ")
	sb.WriteString(b.Severity)
	if len(b.Actors) > 0 {
		sb.WriteString("\nActors: ")
		sb.WriteString(strings.Join(b.Actors, ", "))
	}
	if len(b.Products) > 0 {
		sb.WriteString("\nProducts: ")
		sb.WriteString(strings.Join(b.Products, ", "))
	}
	if len(b.Tags) > 0 {
		sb.WriteString("\nTags: ")
		sb.WriteString(strings.Join(b.Tags, ", "))
	}
	if b.URL != "" {
		sb.WriteString("\n\nFull brief: ")
		sb.WriteString(b.URL)
	}
	if unsubToken != "" && serviceURL != "" {
		sb.WriteString("\n\n---\nUnsubscribe: ")
		sb.WriteString(serviceURL)
		sb.WriteString("/unsubscribe?token=")
		sb.WriteString(unsubToken)
	}
	return sb.String()
}
