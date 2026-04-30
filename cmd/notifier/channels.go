package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// webhookClient is shared across Slack/Teams sends. Reuse the same
// pooled transport.
var webhookClient = &http.Client{Timeout: 10 * time.Second}

// SendSlack posts a brief notification to a Slack incoming webhook.
// Format: a single attachment with severity-coded color, title link,
// and a one-line context with type / actors / products / tags.
func SendSlack(webhook string, b Brief) error {
	payload := map[string]any{
		"text": fmt.Sprintf("%s — %s", strings.ToUpper(b.Severity), b.Title),
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
	return postJSON(webhook, payload)
}

// SendTeams posts a brief notification to a Microsoft Teams incoming
// webhook. Uses the legacy "MessageCard" format which still works on
// Office 365 connectors.
func SendTeams(webhook string, b Brief) error {
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
	return postJSON(webhook, card)
}

func postJSON(url string, body any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
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
