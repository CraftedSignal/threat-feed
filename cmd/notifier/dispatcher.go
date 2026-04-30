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
// debounce. Email recipients are batched onto a single SMTP connection
// per sweep — Workspace's relay throttles per-account login rate, so
// reusing the auth'd session across N subscribers is the difference
// between every flush working and tripping a 24h lockout. Webhook
// channels (Slack/Teams) still post per-subscription in parallel since
// they don't share a connection.
//
// Cleanup: queues are deleted only after a successful delivery and
// MarkSent. Failures leave the queue intact so the next sweep retries.
func (d *dispatcher) FlushPending(ctx context.Context, debounce time.Duration, serviceURL string) (sent int, failed int) {
	// Sliding-window gate. A queue is flushable when EITHER:
	//   - no new briefs arrived in the last `debounce` (idle window) —
	//     the natural end of an activity burst, or
	//   - the oldest brief in the queue is older than `maxAge` — a
	//     hard ceiling so a steady drip can't delay forever.
	now := time.Now().UTC()
	const maxAge = 30 * time.Minute
	idleAge := now.Add(-debounce)
	maxCutoff := now.Add(-maxAge)

	// Collect everything first so SMTP gets one connection regardless
	// of how many email subscribers have pending queues.
	type emailJob struct {
		sub Subscription
		pd  PendingDispatch
		msg SmtpMessage
	}
	var emailJobs []emailJob

	type webhookJob struct {
		sub Subscription
		pd  PendingDispatch
	}
	var webhookJobs []webhookJob

	if err := d.store.ForEachFlushablePending(ctx, idleAge, maxCutoff, func(pd PendingDispatch) error {
		if len(pd.Briefs) == 0 {
			_ = d.store.DeletePending(ctx, pd.SubscriptionID)
			return nil
		}
		sub, err := d.store.GetSubscription(ctx, pd.SubscriptionID)
		if err != nil {
			if err == ErrNotFound {
				_ = d.store.DeletePending(ctx, pd.SubscriptionID)
				return nil
			}
			d.logger.Error("flush: lookup subscription failed", "sub_id", pd.SubscriptionID, "err", err)
			return nil
		}
		switch sub.Channel {
		case ChannelEmail:
			emailJobs = append(emailJobs, emailJob{
				sub: sub, pd: pd,
				msg: SmtpMessage{
					To:      sub.Email,
					Subject: emailSubjectBatch(pd.Briefs),
					Body:    emailBodyBatch(pd.Briefs, serviceURL, sub.UnsubscribeToken),
				},
			})
		case ChannelSlack, ChannelTeams:
			webhookJobs = append(webhookJobs, webhookJob{sub: sub, pd: pd})
		default:
			d.logger.Warn("flush: unknown channel", "sub_id", pd.SubscriptionID, "channel", sub.Channel)
		}
		return nil
	}); err != nil {
		d.logger.Error("flush iteration failed", "err", err)
	}

	// Email batch: one SMTP session for all recipients. Per-recipient
	// errors come back from SendBatch — only delete a queue + bump
	// last_sent for the subscribers whose delivery actually succeeded;
	// the rest stay queued so the next sweep retries.
	if len(emailJobs) > 0 {
		msgs := make([]SmtpMessage, len(emailJobs))
		for i, j := range emailJobs {
			msgs[i] = j.msg
		}
		results := d.mailer.SendBatch(msgs)
		for i, j := range emailJobs {
			if i < len(results) && results[i] != nil {
				failed++
				continue
			}
			_ = d.store.MarkSent(ctx, j.sub.ID, time.Now().UTC())
			_ = d.store.DeletePending(ctx, j.pd.SubscriptionID)
			sent++
		}
	}

	// Webhook channels: still per-subscription, but bounded parallelism.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(dispatchConcurrency)
	for _, w := range webhookJobs {
		w := w
		g.Go(func() error {
			var err error
			switch w.sub.Channel {
			case ChannelSlack:
				err = SendSlackBatch(w.sub.WebhookURL, w.pd.Briefs)
			case ChannelTeams:
				err = SendTeamsBatch(w.sub.WebhookURL, w.pd.Briefs)
			}
			if err != nil {
				d.logger.Error("webhook send failed", "sub_id", w.sub.ID, "channel", w.sub.Channel, "err", err)
				failed++
				return nil
			}
			_ = d.store.MarkSent(gctx, w.sub.ID, time.Now().UTC())
			_ = d.store.DeletePending(gctx, w.pd.SubscriptionID)
			sent++
			return nil
		})
	}
	_ = g.Wait()

	return sent, failed
}

// flushSubscription is the inline overflow path: fetch the queued
// PendingDispatch by ID, deliver, clear. Used when an /dispatch call
// tips a single subscriber over the queue cap.
func (d *dispatcher) flushSubscription(ctx context.Context, subID string, serviceURL string) error {
	pd, err := d.store.GetPending(ctx, subID)
	if err != nil {
		if err == ErrNotFound {
			return nil
		}
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
