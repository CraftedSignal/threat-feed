package main

import (
	"fmt"
	"html"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type emailContent struct {
	Text string
	HTML string
}

func (s *server) verifyEmailContent(token string) emailContent {
	base := s.cfg.ServiceURL
	if base == "" {
		text := fmt.Sprintf(`Your CraftedSignal Threat Feed subscription is awaiting confirmation.

Verification token: %s

SERVICE_URL is not configured. Contact the operator.
`, token)
		return emailContent{
			Text: text,
			HTML: emailShell(
				"Confirm your subscription",
				"CraftedSignal Threat Feed",
				"Your subscription is waiting for confirmation.",
				fmt.Sprintf(`<p style="%s">Use this verification token:</p><p style="%s">%s</p>`, pStyle, codeStyle, h(token)),
			),
		}
	}

	verifyURL := fmt.Sprintf("%s/verify?token=%s", base, token)
	text := fmt.Sprintf(`Confirm your CraftedSignal Threat Feed subscription:

%s

This link expires in 24 hours. If you did not request this, ignore the email.
`, verifyURL)

	body := fmt.Sprintf(`
		<p style="%s">Confirm this address to start receiving matching threat-feed alerts.</p>
		<p style="margin:24px 0 28px"><a href="%s" style="%s">Confirm subscription</a></p>
		<p style="%s">This link expires in 24 hours. If you did not request this, you can ignore this email.</p>
	`, pStyle, hAttr(verifyURL), buttonStyle, mutedStyle)

	return emailContent{
		Text: text,
		HTML: emailShell("Confirm your subscription", "CraftedSignal Threat Feed", "Confirm this address to start receiving alerts.", body),
	}
}

func emailHTMLBatch(briefs []Brief, serviceURL, unsubToken string) string {
	if len(briefs) == 0 {
		return ""
	}

	title := "Brief matched your filter"
	preheader := "A new brief matches your threat-feed subscription."
	if len(briefs) > 1 {
		title = fmt.Sprintf("%d briefs matched your filter", len(briefs))
		preheader = fmt.Sprintf("%d new briefs match your threat-feed subscription.", len(briefs))
	}

	var cards strings.Builder
	for _, b := range briefs {
		cards.WriteString(briefCardHTML(b))
	}

	if unsubToken != "" && serviceURL != "" {
		unsubURL := fmt.Sprintf("%s/unsubscribe?token=%s", serviceURL, unsubToken)
		cards.WriteString(fmt.Sprintf(`
			<div style="border-top:1px solid #e2e8f0;margin-top:26px;padding-top:18px">
				<p style="%s">You are receiving this because a brief matched your CraftedSignal Threat Feed filters.</p>
				<p style="%s"><a href="%s" style="color:#475569;text-decoration:underline">Unsubscribe</a></p>
			</div>
		`, mutedStyle, mutedStyle, hAttr(unsubURL)))
	}

	return emailShell(title, "CraftedSignal Threat Feed", preheader, cards.String())
}

func briefCardHTML(b Brief) string {
	severity := strings.ToLower(strings.TrimSpace(b.Severity))
	if severity == "" {
		severity = "medium"
	}
	typeLabel := strings.TrimSpace(b.Type)
	if typeLabel != "" {
		typeLabel = cases.Title(language.English).String(typeLabel)
	}

	var meta strings.Builder
	writeMeta := func(label string, values []string) {
		if len(values) == 0 {
			return
		}
		meta.WriteString(fmt.Sprintf(`<p style="%s"><strong style="color:#334155">%s:</strong> %s</p>`, metaStyle, h(label), h(strings.Join(values, ", "))))
	}
	writeMeta("Actors", b.Actors)
	writeMeta("Products", b.Products)
	writeMeta("Tags", b.Tags)

	update := ""
	if b.IsUpdate && b.UpdateSummary != "" {
		update = fmt.Sprintf(`<p style="%s"><strong style="color:#334155">Update:</strong> %s</p>`, pStyle, h(b.UpdateSummary))
	}

	link := ""
	if b.URL != "" {
		link = fmt.Sprintf(`<p style="margin:18px 0 0"><a href="%s" style="%s">View brief</a></p>`, hAttr(b.URL), secondaryButtonStyle)
	}

	return fmt.Sprintf(`
		<div style="border:1px solid #e2e8f0;border-radius:12px;padding:18px 18px 16px;margin:0 0 14px;background:#ffffff">
			<div style="margin-bottom:12px">
				<span style="%s">%s</span>
				%s
			</div>
			<h2 style="font-family:Arial,Helvetica,sans-serif;font-size:19px;line-height:1.3;margin:0 0 10px;color:#0f172a">%s</h2>
			%s
			<p style="%s">%s</p>
			%s
			%s
		</div>
	`, severityPillStyle(severity), h(strings.ToUpper(severity)), typePillHTML(typeLabel), h(b.Title), update, pStyle, h(b.Description), meta.String(), link)
}

func typePillHTML(typeLabel string) string {
	if typeLabel == "" {
		return ""
	}
	return fmt.Sprintf(`<span style="display:inline-block;margin-left:8px;border:1px solid #cbd5e1;border-radius:999px;padding:4px 8px;font:700 11px Arial,Helvetica,sans-serif;letter-spacing:.06em;text-transform:uppercase;color:#475569">%s</span>`, h(typeLabel))
}

func emailShell(title, kicker, preheader, body string) string {
	return fmt.Sprintf(`<!doctype html>
<html>
<head>
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<title>%s</title>
</head>
<body style="margin:0;padding:0;background:#f8fafc;color:#0f172a">
	<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">%s</div>
	<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="background:#f8fafc;border-collapse:collapse">
		<tr>
			<td align="center" style="padding:28px 16px">
				<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="max-width:640px;border-collapse:collapse">
					<tr>
						<td style="padding:0 0 14px">
							<p style="margin:0;font:700 12px Arial,Helvetica,sans-serif;letter-spacing:.14em;text-transform:uppercase;color:#475569">%s</p>
						</td>
					</tr>
					<tr>
						<td style="background:#ffffff;border:1px solid #e2e8f0;border-radius:14px;padding:26px 24px">
							<h1 style="font-family:Arial,Helvetica,sans-serif;font-size:26px;line-height:1.2;margin:0 0 18px;color:#0f172a">%s</h1>
							%s
						</td>
					</tr>
					<tr>
						<td style="padding:16px 4px 0">
							<p style="margin:0;font:400 12px/1.5 Arial,Helvetica,sans-serif;color:#64748b">CraftedSignal</p>
						</td>
					</tr>
				</table>
			</td>
		</tr>
	</table>
</body>
</html>`, h(title), h(preheader), h(kicker), h(title), body)
}

func severityPillStyle(severity string) string {
	color := "#475569"
	bg := "#f1f5f9"
	switch severity {
	case "critical":
		color = "#b91c1c"
		bg = "#fef2f2"
	case "high":
		color = "#c2410c"
		bg = "#fff7ed"
	case "medium":
		color = "#a16207"
		bg = "#fefce8"
	case "low":
		color = "#15803d"
		bg = "#f0fdf4"
	}
	return fmt.Sprintf("display:inline-block;border-radius:999px;padding:5px 9px;background:%s;color:%s;font:700 11px Arial,Helvetica,sans-serif;letter-spacing:.06em;text-transform:uppercase", bg, color)
}

func h(v string) string {
	return html.EscapeString(v)
}

func hAttr(v string) string {
	return html.EscapeString(v)
}

const (
	pStyle               = "margin:0 0 14px;font:400 15px/1.55 Arial,Helvetica,sans-serif;color:#334155"
	mutedStyle           = "margin:0 0 10px;font:400 13px/1.5 Arial,Helvetica,sans-serif;color:#64748b"
	metaStyle            = "margin:6px 0 0;font:400 13px/1.45 Arial,Helvetica,sans-serif;color:#64748b"
	codeStyle            = "display:inline-block;margin:8px 0 0;padding:10px 12px;background:#f1f5f9;border:1px solid #cbd5e1;border-radius:8px;font:700 14px/1.4 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;color:#0f172a;word-break:break-all"
	buttonStyle          = "display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;border-radius:10px;padding:12px 18px;font:700 14px Arial,Helvetica,sans-serif"
	secondaryButtonStyle = "display:inline-block;background:#0f172a;color:#ffffff;text-decoration:none;border-radius:9px;padding:10px 14px;font:700 13px Arial,Helvetica,sans-serif"
)
