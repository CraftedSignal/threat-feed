package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// dispatcher fans new briefs out to matching subscriptions.
type dispatcher struct {
	store  *firestoreStore
	mailer mailer
	logger *slog.Logger
}

// Dispatch evaluates each new brief against every verified subscription
// and sends matches via the appropriate channel. Errors per delivery are
// logged but don't fail the batch.
func (d *dispatcher) Dispatch(ctx context.Context, briefs []Brief, serviceURL string) (sent int, failed int) {
	now := time.Now().UTC()
	err := d.store.ForEachVerified(ctx, func(sub Subscription) error {
		for _, b := range briefs {
			if !sub.Filter.Matches(b) {
				continue
			}
			if err := d.deliver(sub, b, serviceURL); err != nil {
				d.logger.Error("delivery failed",
					"sub_id", sub.ID,
					"channel", sub.Channel,
					"brief", b.Slug,
					"err", err)
				failed++
				continue
			}
			sent++
		}
		// Update last_sent best-effort if anything matched. We can't tell
		// from inside the closure how many briefs matched this sub
		// without more bookkeeping, so just mark whenever the sub was
		// considered.
		_ = d.store.MarkSent(ctx, sub.ID, now)
		return nil
	})
	if err != nil {
		d.logger.Error("dispatch iteration failed", "err", err)
	}
	return sent, failed
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
	prefix := "[" + strings.ToUpper(b.Severity) + "]"
	if b.Type != "" {
		prefix += " " + strings.Title(b.Type)
	}
	return prefix + ": " + b.Title
}

func emailBody(b Brief, serviceURL, unsubToken string) string {
	var sb strings.Builder
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
