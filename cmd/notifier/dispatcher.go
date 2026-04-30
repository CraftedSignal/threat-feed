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

// Dispatch is the per-/dispatch hot path. It used to deliver one
// message per (subscription, brief) match — fine for one-brief-per-call
// but spammy when ti-bot pushes a burst. Now matches are enqueued into
// a per-subscription pending_dispatch document; the periodic
// /flush-pending sweep coalesces everything queued in the debounce
// window into a single message per subscriber. A single subscriber's
// queue is force-flushed inline if it would overflow pendingDispatchCap.
//
// Returns (queued, overflow_flushed) — the second number is the count
// of subscribers whose queue tipped over the cap and got flushed
// immediately. Callers log both for observability.
func (d *dispatcher) Dispatch(ctx context.Context, briefs []Brief, serviceURL string) (queued int, overflowFlushed int) {
	var queuedN, flushedN atomic.Int64

	type overflow struct {
		sub Subscription
	}
	var overflows []overflow
	var overflowsMu sync.Mutex

	if err := d.store.ForEachVerified(ctx, func(sub Subscription) error {
		var matched []Brief
		for _, b := range briefs {
			if !sub.Filter.Matches(b) {
				continue
			}
			// Update dispatches reach only subscribers who explicitly
			// opted in. A new-brief dispatch ignores the toggle.
			if b.IsUpdate && !sub.Filter.IncludeUpdates {
				continue
			}
			matched = append(matched, b)
		}
		if len(matched) == 0 {
			return nil
		}
		over, err := d.store.EnqueuePending(ctx, sub.ID, matched)
		if err != nil {
			d.logger.Error("enqueue pending failed", "sub_id", sub.ID, "err", err)
			return nil // keep iterating other subs
		}
		queuedN.Add(int64(len(matched)))
		if over {
			overflowsMu.Lock()
			overflows = append(overflows, overflow{sub: sub})
			overflowsMu.Unlock()
		}
		return nil
	}); err != nil {
		d.logger.Error("dispatch iteration failed", "err", err)
	}

	// Force-flush any subscriber whose queue overflowed the cap. This
	// is rare — ti-bot's normal cadence is well under 50 briefs in a
	// debounce window — but when it happens we don't want the queue
	// silently bouncing later writes.
	for _, o := range overflows {
		if err := d.flushSubscription(ctx, o.sub.ID, serviceURL); err != nil {
			d.logger.Error("overflow flush failed", "sub_id", o.sub.ID, "err", err)
			continue
		}
		flushedN.Add(1)
	}

	return int(queuedN.Load()), int(flushedN.Load())
}

// FlushPending drains every queue with first_queued_at older than
// debounce. For each, fetches the subscription, builds a single
// batched message containing all queued briefs, delivers, and clears
// the queue on success. Failures leave the queue intact for the next
// sweep to retry.
func (d *dispatcher) FlushPending(ctx context.Context, debounce time.Duration, serviceURL string) (sent int, failed int) {
	cutoff := time.Now().UTC().Add(-debounce)
	var sentN, failedN atomic.Int64

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(dispatchConcurrency)

	if err := d.store.ForEachFlushablePending(gctx, cutoff, func(pd PendingDispatch) error {
		pdCopy := pd
		g.Go(func() error {
			pd := pdCopy
			if err := d.flushSubscriptionPending(gctx, pd, serviceURL); err != nil {
				d.logger.Error("flush failed", "sub_id", pd.SubscriptionID, "err", err)
				failedN.Add(1)
				return nil
			}
			sentN.Add(1)
			return nil
		})
		return nil
	}); err != nil {
		d.logger.Error("flush iteration failed", "err", err)
	}

	if err := g.Wait(); err != nil {
		d.logger.Error("flush worker error", "err", err)
	}
	return int(sentN.Load()), int(failedN.Load())
}

// flushSubscription is the inline overflow path: fetch the queued
// PendingDispatch, deliver, clear. Used when an /dispatch call tips
// a single subscriber over the queue cap.
func (d *dispatcher) flushSubscription(ctx context.Context, subID string, serviceURL string) error {
	// Re-query the queue — overflow was decided in the Set transaction
	// above, but the deliverable shape lives in the doc.
	var pd PendingDispatch
	if err := d.store.ForEachFlushablePending(ctx, time.Now().UTC().Add(time.Hour), func(p PendingDispatch) error {
		if p.SubscriptionID == subID {
			pd = p
		}
		return nil
	}); err != nil {
		return err
	}
	if len(pd.Briefs) == 0 {
		return nil
	}
	return d.flushSubscriptionPending(ctx, pd, serviceURL)
}

// flushSubscriptionPending pairs a queued PendingDispatch with its
// subscription and emits the batched message.
func (d *dispatcher) flushSubscriptionPending(ctx context.Context, pd PendingDispatch, serviceURL string) error {
	if len(pd.Briefs) == 0 {
		return d.store.DeletePending(ctx, pd.SubscriptionID)
	}
	sub, err := d.store.GetSubscription(ctx, pd.SubscriptionID)
	if err != nil {
		// Subscription gone — clear the orphan queue.
		if err == ErrNotFound {
			_ = d.store.DeletePending(ctx, pd.SubscriptionID)
			return nil
		}
		return err
	}
	if err := d.deliverBatch(sub, pd.Briefs, serviceURL); err != nil {
		return err
	}
	if err := d.store.DeletePending(ctx, pd.SubscriptionID); err != nil {
		d.logger.Warn("delete pending after delivery failed", "sub_id", pd.SubscriptionID, "err", err)
	}
	_ = d.store.MarkSent(ctx, pd.SubscriptionID, time.Now().UTC())
	return nil
}

// deliverBatch sends one message per subscription channel covering all
// queued briefs. The unbatched per-brief deliver path is gone — every
// delivery now flows through here, even single-brief queues.
func (d *dispatcher) deliverBatch(sub Subscription, briefs []Brief, serviceURL string) error {
	if len(briefs) == 0 {
		return nil
	}
	switch sub.Channel {
	case ChannelEmail:
		return d.mailer.Send(sub.Email, emailSubjectBatch(briefs), emailBodyBatch(briefs, serviceURL, sub.UnsubscribeToken))
	case ChannelSlack:
		return SendSlackBatch(sub.WebhookURL, briefs)
	case ChannelTeams:
		return SendTeamsBatch(sub.WebhookURL, briefs)
	default:
		return fmt.Errorf("unknown channel: %q", sub.Channel)
	}
}

// emailSubjectBatch produces a single-line subject for a batch
// notification. For one brief: keep the original "[SEV] Type: title"
// format so single-item alerts read the same as before. For >1: lead
// with the highest severity in the batch and include a count.
func emailSubjectBatch(briefs []Brief) string {
	if len(briefs) == 1 {
		b := briefs[0]
		if b.IsUpdate {
			return "[UPDATE] " + b.Title + " — " + strings.ToUpper(b.Severity)
		}
		prefix := "[" + strings.ToUpper(b.Severity) + "]"
		if b.Type != "" {
			prefix += " " + cases.Title(language.English).String(b.Type)
		}
		return prefix + ": " + b.Title
	}
	top := topSeverity(briefs)
	return fmt.Sprintf("[%s+%d more] %d new briefs match your filter", strings.ToUpper(top), len(briefs)-1, len(briefs))
}

// severityRank orders severity strings so we can pick the highest in a
// batch for the subject line. Unknown values rank as 0.
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "rumour":
		return 1
	}
	return 0
}

func topSeverity(briefs []Brief) string {
	top := ""
	rank := -1
	for _, b := range briefs {
		if r := severityRank(b.Severity); r > rank {
			rank = r
			top = b.Severity
		}
	}
	return top
}

func emailBodyBatch(briefs []Brief, serviceURL, unsubToken string) string {
	var sb strings.Builder
	if len(briefs) == 1 {
		// Single-brief path: keep the legacy detailed body so existing
		// subscribers don't see a regression on the most common case.
		b := briefs[0]
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
	} else {
		// Multi-brief: compact list. One line of metadata per brief
		// (severity / type / title) plus its description and link.
		fmt.Fprintf(&sb, "%d briefs match your filter:\n\n", len(briefs))
		for _, b := range briefs {
			prefix := "[" + strings.ToUpper(b.Severity) + "]"
			if b.IsUpdate {
				prefix = "[UPDATE]"
			} else if b.Type != "" {
				prefix += " " + cases.Title(language.English).String(b.Type)
			}
			fmt.Fprintf(&sb, "%s %s\n", prefix, b.Title)
			if b.Description != "" {
				sb.WriteString(b.Description)
				sb.WriteString("\n")
			}
			if b.URL != "" {
				sb.WriteString(b.URL)
				sb.WriteString("\n")
			}
			sb.WriteString("\n")
		}
	}
	if unsubToken != "" && serviceURL != "" {
		sb.WriteString("\n---\nUnsubscribe: ")
		sb.WriteString(serviceURL)
		sb.WriteString("/unsubscribe?token=")
		sb.WriteString(unsubToken)
	}
	return sb.String()
}
