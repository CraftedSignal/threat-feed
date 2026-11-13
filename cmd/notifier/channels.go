package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// webhookClient is shared across Slack/Teams sends. Reuse the same
// pooled transport.
var webhookClient = newWebhookHTTPClient()

var (
	webhookRetryDelays = []time.Duration{1 * time.Second, 2 * time.Second}
	webhookRetryBudget = 30 * time.Second
)

// SendSlack posts a brief notification to a Slack incoming webhook.
// Format: a single attachment with severity-coded color, title link,
// and a one-line context with type / actors / products / tags.
func SendSlack(webhook string, b Brief) error {
	return SendSlackContext(context.Background(), webhook, b)
}

func SendSlackContext(ctx context.Context, webhook string, b Brief) error {
	payload := map[string]any{
		"text": fmt.Sprintf("%s - %s", strings.ToUpper(b.Severity), b.Title),
		"attachments": []map[string]any{{
			"color":      slackColor(b.Severity),
			"title":      b.Title,
			"title_link": b.URL,
			"text":       b.Description,
			"fields": []map[string]any{
				{"title": "Type", "value": b.Type, "short": true},
				{"title": "Severity", "value": b.Severity, "short": true},
			},
			"footer": footerLine(b),
		}},
	}
	return postWebhookJSONContext(ctx, ChannelSlack, webhook, payload)
}

// SendTeams posts a brief notification to a Microsoft Teams incoming
// webhook. Uses the legacy "MessageCard" format which still works on
// Office 365 connectors.
func SendTeams(webhook string, b Brief) error {
	return SendTeamsContext(context.Background(), webhook, b)
}

func SendTeamsContext(ctx context.Context, webhook string, b Brief) error {
	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"themeColor": teamsColor(b.Severity),
		"summary":    b.Title,
		"title":      b.Title,
		"text":       b.Description,
		"sections": []map[string]any{{
			"facts": []map[string]any{
				{"name": "Type", "value": b.Type},
				{"name": "Severity", "value": b.Severity},
				{"name": "Tags", "value": strings.Join(b.Tags, ", ")},
			},
		}},
		"potentialAction": []map[string]any{{
			"@type":   "OpenUri",
			"name":    "View brief",
			"targets": []map[string]any{{"os": "default", "uri": b.URL}},
		}},
	}
	return postWebhookJSONContext(ctx, ChannelTeams, webhook, card)
}

// maxSlackAttachments caps the number of legacy attachments in a single
// Slack message. Slack rejects payloads with too many attachments, so excess
// briefs are folded into a tail summary.
const maxSlackAttachments = 20

// SendSlackBatch posts a single Slack message containing multiple
// briefs as separate attachments. Single-brief case mirrors SendSlack
// so existing webhook recipients see no regression.
func SendSlackBatch(webhook string, briefs []Brief) error {
	return SendSlackBatchContext(context.Background(), webhook, briefs)
}

func SendSlackBatchContext(ctx context.Context, webhook string, briefs []Brief) error {
	if len(briefs) == 0 {
		return nil
	}
	if len(briefs) == 1 {
		return SendSlackContext(ctx, webhook, briefs[0])
	}
	atts := make([]map[string]any, 0, len(briefs))
	top := ""
	for _, b := range briefs {
		atts = append(atts, map[string]any{
			"color":      slackColor(b.Severity),
			"title":      b.Title,
			"title_link": b.URL,
			"text":       b.Description,
			"fields": []map[string]any{
				{"title": "Type", "value": b.Type, "short": true},
				{"title": "Severity", "value": b.Severity, "short": true},
			},
			"footer": footerLine(b),
		})
		if severityRank(b.Severity) > severityRank(top) {
			top = b.Severity
		}
	}
	tail := 0
	if len(atts) > maxSlackAttachments {
		tail = len(atts) - maxSlackAttachments
		atts = atts[:maxSlackAttachments]
		atts = append(atts, map[string]any{
			"color": "#94a3b8",
			"text":  fmt.Sprintf("…and %d more briefs.", tail),
		})
	}
	payload := map[string]any{
		"text":        fmt.Sprintf("%s+%d more - %d briefs match your filter", strings.ToUpper(top), len(briefs)-1, len(briefs)),
		"attachments": atts,
	}
	return postWebhookJSONContext(ctx, ChannelSlack, webhook, payload)
}

// SendTeamsBatch sends a Teams MessageCard with one section per brief.
// Limited to ~10 sections to stay under Teams' card-size constraints;
// excess briefs are summarized in a tail note.
func SendTeamsBatch(webhook string, briefs []Brief) error {
	return SendTeamsBatchContext(context.Background(), webhook, briefs)
}

func SendTeamsBatchContext(ctx context.Context, webhook string, briefs []Brief) error {
	if len(briefs) == 0 {
		return nil
	}
	if len(briefs) == 1 {
		return SendTeamsContext(ctx, webhook, briefs[0])
	}
	const maxSections = 10
	render := briefs
	tail := 0
	if len(render) > maxSections {
		tail = len(render) - maxSections
		render = render[:maxSections]
	}
	sections := make([]map[string]any, 0, len(render)+1)
	top := ""
	for _, b := range render {
		sections = append(sections, map[string]any{
			"activityTitle":    b.Title,
			"activitySubtitle": fmt.Sprintf("%s · %s", b.Type, b.Severity),
			"text":             b.Description,
			"facts": []map[string]any{
				{"name": "Tags", "value": strings.Join(b.Tags, ", ")},
				{"name": "Link", "value": b.URL},
			},
		})
		if severityRank(b.Severity) > severityRank(top) {
			top = b.Severity
		}
	}
	if tail > 0 {
		sections = append(sections, map[string]any{
			"text": fmt.Sprintf("…and %d more.", tail),
		})
	}
	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"themeColor": teamsColor(top),
		"summary":    fmt.Sprintf("%d new briefs", len(briefs)),
		"title":      fmt.Sprintf("%d briefs match your filter", len(briefs)),
		"sections":   sections,
	}
	return postWebhookJSONContext(ctx, ChannelTeams, webhook, card)
}

func SendWebhookWelcome(channel Channel, webhook, siteURL string) error {
	switch channel {
	case ChannelSlack:
		payload := map[string]any{
			"text": "CraftedSignal Threat Feed subscription confirmed. Alerts matching your filters will appear here.",
		}
		if siteURL != "" {
			payload["attachments"] = []map[string]any{{
				"color": "#22c55e",
				"text":  "Manage this subscription from the CraftedSignal Threat Feed site.",
				"actions": []map[string]any{{
					"type": "button",
					"text": "Open feed",
					"url":  siteURL,
				}},
			}}
		}
		return postWebhookJSON(channel, webhook, payload)
	case ChannelTeams:
		card := map[string]any{
			"@type":      "MessageCard",
			"@context":   "https://schema.org/extensions",
			"themeColor": "22C55E",
			"summary":    "CraftedSignal Threat Feed subscription confirmed",
			"title":      "CraftedSignal Threat Feed subscription confirmed",
			"text":       "Alerts matching your filters will appear here.",
		}
		if siteURL != "" {
			card["potentialAction"] = []map[string]any{{
				"@type":   "OpenUri",
				"name":    "Open feed",
				"targets": []map[string]any{{"os": "default", "uri": siteURL}},
			}}
		}
		return postWebhookJSON(channel, webhook, card)
	default:
		return fmt.Errorf("unsupported webhook channel %q", channel)
	}
}

// invalidWebhookURLError marks a webhook URL rejected by validation
// (bad scheme, host, port, or a literal blocked IP).
type invalidWebhookURLError struct{ Err error }

func (e *invalidWebhookURLError) Error() string { return "invalid webhook URL" }
func (e *invalidWebhookURLError) Unwrap() error { return e.Err }

// blockedWebhookIPError marks a webhook target that resolved to a
// non-public address (SSRF guard).
type blockedWebhookIPError struct{ IP net.IP }

func (e *blockedWebhookIPError) Error() string {
	return fmt.Sprintf("webhook resolved to blocked IP %s", e.IP)
}

// unreachableWebhookError marks a transport-level failure reaching an
// allowed target (DNS failure, refused connection, timeout, TLS).
type unreachableWebhookError struct{ Err error }

func (e *unreachableWebhookError) Error() string {
	category := "transport"
	var networkError net.Error
	var dnsError *net.DNSError
	var certificateError *tls.CertificateVerificationError
	var recordError tls.RecordHeaderError
	switch {
	case errors.Is(e.Err, context.DeadlineExceeded), errors.As(e.Err, &networkError) && networkError.Timeout():
		category = "timeout"
	case errors.As(e.Err, &dnsError):
		category = "DNS"
	case errors.As(e.Err, &certificateError), errors.As(e.Err, &recordError):
		category = "TLS"
	case errors.Is(e.Err, syscall.ECONNREFUSED):
		category = "connection refused"
	case errors.Is(e.Err, syscall.ECONNRESET):
		category = "connection reset"
	case errors.Is(e.Err, io.EOF), errors.Is(e.Err, io.ErrUnexpectedEOF):
		category = "connection closed"
	}
	return "webhook target unreachable: " + category
}
func (e *unreachableWebhookError) Unwrap() error { return e.Err }

// webhookStatusError marks a target that answered with a non-2xx status.
type webhookStatusError struct {
	Code       int
	Body       string // retained for internal diagnostics; Error never exposes response content.
	RetryAfter time.Duration
	RetryAt    time.Time
}

func (e *webhookStatusError) Error() string {
	return fmt.Sprintf("webhook HTTP %d", e.Code)
}

// classifyWebhookVerifyError maps a webhook send error to the HTTP status
// and public message for /subscribe. clientErr is true when the failure is
// caused by the subscriber's input rather than our own service.
func classifyWebhookVerifyError(err error) (status int, msg string, clientErr bool) {
	var (
		blocked *blockedWebhookIPError
		invalid *invalidWebhookURLError
		unreach *unreachableWebhookError
		st      *webhookStatusError
	)
	switch {
	case errors.As(err, &blocked), errors.As(err, &invalid):
		return http.StatusBadRequest, "invalid webhook URL", true
	case errors.As(err, &unreach), errors.As(err, &st):
		return http.StatusUnprocessableEntity, "webhook verification failed: target unreachable or rejected the test message", true
	default:
		return http.StatusBadGateway, "webhook verification failed", false
	}
}

func postWebhookJSON(channel Channel, rawURL string, body any) error {
	return postWebhookJSONContext(context.Background(), channel, rawURL, body)
}

func postWebhookJSONContext(ctx context.Context, channel Channel, rawURL string, body any) error {
	webhookURL, err := validateWebhookURL(rawURL, channel)
	if err != nil {
		return &invalidWebhookURLError{Err: err}
	}
	if !externalWebhookURLPattern.MatchString(webhookURL) {
		return &invalidWebhookURLError{Err: fmt.Errorf("invalid webhook URL")}
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	delays := webhookRetryDelays
	started := time.Now()
	var lastErr error
	for attempt := 0; attempt <= len(delays); attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt > 0 {
			wait := delays[attempt-1]
			if se, ok := lastErr.(*webhookStatusError); ok && se.Code == http.StatusTooManyRequests && se.RetryAfter > 0 {
				wait = se.RetryAfter
			}
			if time.Since(started) > webhookRetryBudget || wait > time.Until(started.Add(webhookRetryBudget)) {
				if se, ok := lastErr.(*webhookStatusError); ok && se.Code == http.StatusTooManyRequests {
					se.RetryAt = time.Now().Add(wait)
					return se
				}
				return lastErr
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}

		attemptCtx, cancel := context.WithDeadline(ctx, started.Add(webhookRetryBudget))
		req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, webhookURL, bytes.NewReader(buf))
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := webhookClient.Do(req)
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var blocked *blockedWebhookIPError
			if errors.As(err, &blocked) {
				return fmt.Errorf("webhook request failed: %w", blocked)
			}
			lastErr = fmt.Errorf("webhook request failed: %w", &unreachableWebhookError{Err: err})
			if !isRetryableWebhookError(err) {
				return lastErr
			}
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode < 300 {
			return nil
		}
		lastErr = &webhookStatusError{Code: resp.StatusCode, Body: string(bodyBytes)}
		if resp.StatusCode == http.StatusTooManyRequests {
			se := lastErr.(*webhookStatusError)
			se.RetryAfter = parseWebhookRetryAfter(resp.Header.Get("Retry-After"), time.Now())
			if se.RetryAfter > 0 {
				se.RetryAt = time.Now().Add(se.RetryAfter)
			}
		}
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
			return lastErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if se, ok := lastErr.(*webhookStatusError); ok && se.Code == http.StatusTooManyRequests && se.RetryAfter > 0 {
		se.RetryAt = time.Now().Add(se.RetryAfter)
		return se
	}
	return fmt.Errorf("webhook failed after %d attempts: %w", len(delays)+1, lastErr)
}

func isRetryableWebhookError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ETIMEDOUT) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) {
		if nerr.Timeout() {
			return true
		}
	}
	// Temporary is not a useful classification for arbitrary network errors.
	// DNS exposes an explicit retryable resolver failure independently of timeouts.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTemporary
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return isRetryableWebhookError(ue.Err)
	}
	return false
}

func parseWebhookRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	const maxRetryAfter = 365 * 24 * time.Hour
	if secs, err := strconv.ParseInt(value, 10, 64); err == nil && secs >= 0 {
		if secs > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		if delay := at.Sub(now); delay > maxRetryAfter {
			return maxRetryAfter
		} else {
			return delay
		}
	}
	return 0
}

func slackColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "danger"
	case "high":
		return "warning"
	case "medium":
		return "#caa804"
	case "low":
		return "good"
	default:
		return "#94a3b8"
	}
}

func teamsColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "DC2626"
	case "high":
		return "EA580C"
	case "medium":
		return "CAA804"
	case "low":
		return "16A34A"
	default:
		return "94A3B8"
	}
}

func footerLine(b Brief) string {
	parts := []string{}
	if len(b.Actors) > 0 {
		parts = append(parts, "actors: "+strings.Join(b.Actors, ", "))
	}
	if len(b.Products) > 0 {
		parts = append(parts, "products: "+strings.Join(b.Products, ", "))
	}
	if len(b.Tags) > 0 {
		parts = append(parts, "tags: "+strings.Join(b.Tags, ", "))
	}
	return strings.Join(parts, " · ")
}
