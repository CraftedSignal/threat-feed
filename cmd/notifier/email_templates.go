package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type emailContent struct {
	Text string
	HTML string
}

type emailShellData struct {
	Title     string
	Kicker    string
	Intro     string
	Preheader string
	Body      template.HTML
}

type alertEmailData struct {
	Cards          []briefEmailCard
	UnsubscribeURL string
}

type briefEmailCard struct {
	Title        string
	Description  string
	URL          string
	Badges       []emailBadge
	Meta         []emailMeta
	Update       string
	CardStyle    template.CSS
	TitleStyle   template.CSS
	PrimaryLabel string
}

type emailBadge struct {
	Label string
	Style template.CSS
}

type emailMeta struct {
	Label string
	Value string
}

func (s *server) verifyEmailContent(token string) (emailContent, error) {
	verifyURL := ""
	base := strings.TrimRight(s.cfg.ServiceURL, "/")
	if base != "" {
		verifyURL = fmt.Sprintf("%s/verify?token=%s", base, url.QueryEscape(token))
	}

	data := struct {
		VerifyURL string
		Token     string
	}{VerifyURL: verifyURL, Token: token}
	body, err := renderEmailTemplate(verifyEmailBodyTemplate, data)
	if err != nil {
		return emailContent{}, fmt.Errorf("rendering verify email body: %w", err)
	}
	shell, err := emailShell(emailShellData{
		Title:     "Confirm subscription",
		Kicker:    "Threat Feed",
		Intro:     "Confirm this address to receive matching threat-feed alerts.",
		Preheader: "Confirm this address to start receiving CraftedSignal Threat Feed alerts.",
		Body:      template.HTML(body),
	})
	if err != nil {
		return emailContent{}, fmt.Errorf("rendering verify email shell: %w", err)
	}

	if verifyURL == "" {
		text := fmt.Sprintf(`Your CraftedSignal Threat Feed subscription is awaiting confirmation.

Verification token: %s

SERVICE_URL is not configured. Contact the operator.
`, token)
		return emailContent{Text: text, HTML: shell}, nil
	}

	text := fmt.Sprintf(`Confirm your CraftedSignal Threat Feed subscription:

%s

This link expires in 24 hours. If you did not request this, ignore this email.
`, verifyURL)

	return emailContent{Text: text, HTML: shell}, nil
}

func emailHTMLBatch(briefs []Brief, serviceURL, unsubToken string) (string, error) {
	if len(briefs) == 0 {
		return "", nil
	}

	title := "Brief matched filter"
	preheader := "A new threat-feed brief matches your subscription."
	if len(briefs) > 1 {
		title = fmt.Sprintf("%d briefs matched filter", len(briefs))
		preheader = fmt.Sprintf("%d threat-feed briefs match your subscription.", len(briefs))
	} else if briefs[0].IsUpdate {
		title = "Brief update matched filter"
		preheader = "A threat-feed brief was updated with high-impact context."
	}

	data := alertEmailData{
		Cards: make([]briefEmailCard, 0, len(briefs)),
	}
	for _, b := range briefs {
		data.Cards = append(data.Cards, newBriefEmailCard(b))
	}

	if serviceURL != "" && unsubToken != "" {
		base := strings.TrimRight(serviceURL, "/")
		data.UnsubscribeURL = fmt.Sprintf("%s/unsubscribe?token=%s", base, url.QueryEscape(unsubToken))
	}

	body, err := renderEmailTemplate(alertEmailBodyTemplate, data)
	if err != nil {
		return "", fmt.Errorf("rendering alert email body: %w", err)
	}
	return emailShell(emailShellData{
		Title:     title,
		Kicker:    "Threat Feed",
		Intro:     preheader,
		Preheader: preheader,
		Body:      template.HTML(body),
	})
}

func newBriefEmailCard(b Brief) briefEmailCard {
	severity := normalizeSeverity(b.Severity)
	card := briefEmailCard{
		Title:        b.Title,
		Description:  b.Description,
		URL:          b.URL,
		Update:       b.UpdateSummary,
		CardStyle:    template.CSS(cardStyle(severity)),
		TitleStyle:   template.CSS(titleLinkStyle),
		PrimaryLabel: "View brief",
		Badges: []emailBadge{
			{Label: severityLabel(severity), Style: template.CSS(severityPillStyle(severity))},
		},
	}

	if b.IsUpdate {
		card.Badges = append(card.Badges, emailBadge{Label: "UPDATE", Style: template.CSS(updatePillStyle)})
		card.PrimaryLabel = "View update"
	}
	if b.Type != "" {
		card.Badges = append(card.Badges, emailBadge{
			Label: typeLabel(b.Type),
			Style: template.CSS(typePillStyle(b.Type)),
		})
	}
	if b.Exploited {
		card.Badges = append(card.Badges, emailBadge{Label: "EXPLOITED", Style: template.CSS(exploitedPillStyle)})
	}

	addMeta := func(label string, values []string) {
		if len(values) == 0 {
			return
		}
		card.Meta = append(card.Meta, emailMeta{
			Label: label,
			Value: strings.Join(values, ", "),
		})
	}
	addMeta("Actors", b.Actors)
	addMeta("Vendors", b.Vendors)
	addMeta("Products", b.Products)
	addMeta("Tags", b.Tags)

	return card
}

func emailShell(data emailShellData) (string, error) {
	return renderEmailTemplate(emailShellTemplate, data)
}

func renderEmailTemplate(t *template.Template, data any) (string, error) {
	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium", "low", "rumour", "informational":
		return strings.ToLower(strings.TrimSpace(severity))
	case "info":
		return "informational"
	default:
		return "medium"
	}
}

func severityLabel(severity string) string {
	if severity == "informational" {
		return "INFO"
	}
	return strings.ToUpper(severity)
}

func typeLabel(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "coverage" {
		return "RULE"
	}
	return strings.ToUpper(cases.Title(language.English).String(t))
}

func cardStyle(severity string) string {
	return baseCardStyle + "border-left:4px solid " + severityColor(severity) + ";"
}

func severityColor(severity string) string {
	switch severity {
	case "critical":
		return "#dc2626"
	case "high":
		return "#ea580c"
	case "medium":
		return "#ca8a04"
	case "low":
		return "#16a34a"
	case "rumour", "informational":
		return "#64748b"
	default:
		return "#ca8a04"
	}
}

func severityPillStyle(severity string) string {
	switch severity {
	case "critical":
		return pillBaseStyle + "background:#fee2e2;color:#dc2626;"
	case "high":
		return pillBaseStyle + "background:#ffedd5;color:#ea580c;"
	case "medium":
		return pillBaseStyle + "background:#fef9c3;color:#ca8a04;"
	case "low":
		return pillBaseStyle + "background:#dcfce7;color:#16a34a;"
	case "rumour", "informational":
		return pillBaseStyle + "background:#f1f5f9;color:#64748b;"
	default:
		return pillBaseStyle + "background:#fef9c3;color:#ca8a04;"
	}
}

func typePillStyle(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "threat":
		return pillBaseStyle + "background:#fee2e2;color:#dc2626;"
	case "coverage":
		return pillBaseStyle + "background:#dbeafe;color:#2563eb;"
	case "advisory":
		return pillBaseStyle + "background:#fef9c3;color:#ca8a04;"
	case "rumour":
		return pillBaseStyle + "background:#f1f5f9;color:#64748b;"
	default:
		return pillBaseStyle + "background:#e0f2fe;color:#0369a1;"
	}
}

var (
	emailShellTemplate = template.Must(template.New("email-shell").Parse(`<!doctype html>
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>{{ .Title }}</title>
  <style>
    @font-face{font-family:'Inter';font-style:normal;font-weight:400;src:url('https://feed.craftedsignal.io/fonts/inter-latin-400-normal.woff2') format('woff2')}
    @font-face{font-family:'Inter';font-style:normal;font-weight:600;src:url('https://feed.craftedsignal.io/fonts/inter-latin-600-normal.woff2') format('woff2')}
    @font-face{font-family:'Space Grotesk';font-style:normal;font-weight:700;src:url('https://feed.craftedsignal.io/fonts/space-grotesk-latin-700-normal.woff2') format('woff2')}
    @media only screen and (max-width:620px){
      .cs-page-pad{padding:18px 14px 26px!important}
      .cs-title{font-size:25px!important;line-height:1.16!important}
      .cs-card-cell{padding:17px 16px!important}
      .cs-button{display:block!important;text-align:center!important}
    }
  </style>
</head>
<body style="margin:0;padding:0;background:#f7f9fc;color:#0f172a;-webkit-text-size-adjust:100%;text-size-adjust:100%;">
  <div style="display:none;max-height:0;overflow:hidden;mso-hide:all;color:transparent;opacity:0;">{{ .Preheader }}</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;background:#f7f9fc;">
    <tr>
      <td class="cs-page-pad" style="padding:28px 32px 36px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;">
          <tr>
            <td style="padding:0 0 20px;border-bottom:1px solid #d1dae8;">
              <a href="https://feed.craftedsignal.io/" style="display:inline-block;text-decoration:none;font-family:'Space Grotesk','Inter',Arial,Helvetica,sans-serif;font-size:20px;line-height:1.1;font-weight:700;">
                <span style="color:#2563eb;">crafted</span><span style="color:#0f172a;">signal</span><span style="color:#475569;font-family:ui-monospace,SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;font-size:13px;font-weight:600;"> / feed</span>
              </a>
            </td>
          </tr>
          <tr>
            <td style="padding:24px 0 20px;">
              <p style="margin:0 0 8px;font-family:ui-monospace,SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;font-size:12px;line-height:1.4;font-weight:700;color:#2563eb;text-transform:uppercase;letter-spacing:0;">{{ .Kicker }}</p>
              <h1 class="cs-title" style="margin:0;color:#0f172a;font-family:'Space Grotesk','Inter',Arial,Helvetica,sans-serif;font-size:34px;line-height:1.12;font-weight:700;letter-spacing:0;">{{ .Title }}</h1>
              <p style="margin:12px 0 0;color:#475569;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:15px;line-height:1.55;font-weight:400;">{{ .Intro }}</p>
            </td>
          </tr>
          <tr>
            <td style="padding:0;">
              {{ .Body }}
            </td>
          </tr>
          <tr>
            <td style="padding:24px 0 0;">
              <p style="margin:0;color:#64748b;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:12px;line-height:1.5;">CraftedSignal Threat Feed</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`))

	verifyEmailBodyTemplate = template.Must(template.New("verify-email-body").Parse(`{{ if .VerifyURL }}
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;">
  <tr>
    <td style="padding:0 0 22px;">
      <p style="margin:0;color:#334155;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:15px;line-height:1.6;">Use the button below to confirm this address. The link expires in 24 hours.</p>
    </td>
  </tr>
  <tr>
    <td style="padding:0 0 26px;">
      <a class="cs-button" href="{{ .VerifyURL }}" style="display:inline-block;border-radius:8px;background:#2563eb;color:#ffffff;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:14px;line-height:1;font-weight:700;text-decoration:none;padding:14px 18px;">Confirm subscription</a>
    </td>
  </tr>
  <tr>
    <td style="padding:18px 0 0;border-top:1px solid #d1dae8;">
      <p style="margin:0;color:#64748b;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:13px;line-height:1.55;">If you did not request this subscription, ignore this email.</p>
    </td>
  </tr>
</table>
{{ else }}
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;">
  <tr>
    <td style="padding:0 0 12px;">
      <p style="margin:0;color:#334155;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:15px;line-height:1.6;">The notifier is missing its public service URL. Give this token to an operator to confirm the address manually.</p>
    </td>
  </tr>
  <tr>
    <td style="padding:14px 16px;border-radius:8px;background:#ffffff;border:1px solid #d1dae8;color:#0f172a;font-family:ui-monospace,SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;font-size:14px;line-height:1.4;">{{ .Token }}</td>
  </tr>
</table>
{{ end }}`))

	alertEmailBodyTemplate = template.Must(template.New("alert-email-body").Parse(`{{ range .Cards }}
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="{{ .CardStyle }}">
  <tr>
    <td class="cs-card-cell" style="padding:20px 22px 22px;">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;">
        <tr>
          <td style="padding:0 0 12px;">
            {{ range .Badges }}<span style="{{ .Style }}">{{ .Label }}</span> {{ end }}
          </td>
        </tr>
        <tr>
          <td style="padding:0;">
            {{ if .URL }}<a href="{{ .URL }}" style="{{ .TitleStyle }}">{{ .Title }}</a>{{ else }}<span style="{{ .TitleStyle }}">{{ .Title }}</span>{{ end }}
          </td>
        </tr>
        {{ if .Update }}
        <tr>
          <td style="padding:12px 0 0;">
            <p style="margin:0;color:#334155;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:14px;line-height:1.55;"><strong style="color:#0f172a;">Update:</strong> {{ .Update }}</p>
          </td>
        </tr>
        {{ end }}
        {{ if .Description }}
        <tr>
          <td style="padding:12px 0 0;">
            <p style="margin:0;color:#334155;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:15px;line-height:1.58;">{{ .Description }}</p>
          </td>
        </tr>
        {{ end }}
        {{ if .Meta }}
        <tr>
          <td style="padding:16px 0 0;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;">
              {{ range .Meta }}
              <tr>
                <td style="padding:3px 0;color:#64748b;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:13px;line-height:1.45;">
                  <strong style="color:#334155;">{{ .Label }}:</strong> {{ .Value }}
                </td>
              </tr>
              {{ end }}
            </table>
          </td>
        </tr>
        {{ end }}
        {{ if .URL }}
        <tr>
          <td style="padding:18px 0 0;">
            <a class="cs-button" href="{{ .URL }}" style="display:inline-block;border-radius:8px;border:1px solid #d1dae8;color:#2563eb;background:#ffffff;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:13px;line-height:1;font-weight:700;text-decoration:none;padding:11px 13px;">{{ .PrimaryLabel }}</a>
          </td>
        </tr>
        {{ end }}
      </table>
    </td>
  </tr>
</table>
<div style="height:14px;line-height:14px;font-size:14px;">&nbsp;</div>
{{ end }}
{{ if .UnsubscribeURL }}
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;border-top:1px solid #d1dae8;margin-top:8px;">
  <tr>
    <td style="padding:18px 0 0;">
      <p style="margin:0;color:#64748b;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:13px;line-height:1.55;">You are receiving this because a brief matched your CraftedSignal Threat Feed filters.</p>
      <p style="margin:8px 0 0;color:#64748b;font-family:'Inter',Arial,Helvetica,sans-serif;font-size:13px;line-height:1.55;"><a href="{{ .UnsubscribeURL }}" style="color:#475569;text-decoration:underline;">Unsubscribe</a></p>
    </td>
  </tr>
</table>
{{ end }}`))
)

const (
	baseCardStyle      = "width:100%;border-collapse:separate;border-spacing:0;background:#ffffff;border:1px solid #d1dae8;border-radius:8px;"
	pillBaseStyle      = "display:inline-block;border-radius:4px;padding:5px 8px;margin:0 6px 6px 0;font-family:ui-monospace,SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace;font-size:11px;line-height:1;font-weight:700;text-transform:uppercase;letter-spacing:0;"
	updatePillStyle    = pillBaseStyle + "background:#ccfbf1;color:#0f766e;"
	exploitedPillStyle = pillBaseStyle + "background:#fff7ed;color:#ea580c;border:1px solid #fed7aa;"
	titleLinkStyle     = "display:inline-block;color:#0f172a;font-family:'Space Grotesk','Inter',Arial,Helvetica,sans-serif;font-size:22px;line-height:1.22;font-weight:700;text-decoration:none;letter-spacing:0;"
)
