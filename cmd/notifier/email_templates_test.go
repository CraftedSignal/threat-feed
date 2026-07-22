package main

import (
	"strings"
	"testing"
)

func TestEmailHTMLBatchUsesBrandedFullWidthLayout(t *testing.T) {
	html, err := emailHTMLBatch([]Brief{{
		Title:       "Critical provider outage",
		Description: "New coverage is available.",
		URL:         "https://feed.craftedsignal.io/briefs/provider-outage/",
		Type:        "coverage",
		Severity:    "critical",
	}}, "https://notify.example", "tok")
	if err != nil {
		t.Fatalf("emailHTMLBatch failed: %v", err)
	}

	for _, want := range []string{
		"width:100%",
		"Space Grotesk",
		"crafted</span><span style=\"color:#0f172a;\">signal</span>",
		"border-left:4px solid #dc2626",
		"background:#dbeafe;color:#2563eb",
		"https://notify.example/unsubscribe?token=tok",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("email HTML missing %q\n---\n%s", want, html)
		}
	}
}

func TestEmailHTMLBatchEscapesBriefFieldsAndSanitizesLinks(t *testing.T) {
	html, err := emailHTMLBatch([]Brief{{
		Title:       `<script>alert("x")</script>`,
		Description: `Use <b>safe</b> output`,
		URL:         "javascript:alert(1)",
		Type:        "threat",
		Severity:    "high",
		Actors:      []string{`<img src=x onerror=alert(1)>`},
	}}, "https://notify.example", "tok")
	if err != nil {
		t.Fatalf("emailHTMLBatch failed: %v", err)
	}

	if strings.Contains(html, "<script>") || strings.Contains(html, "<b>safe</b>") || strings.Contains(html, "<img") {
		t.Fatalf("email HTML contains unescaped user-controlled markup:\n%s", html)
	}
	for _, want := range []string{
		"&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;",
		"Use &lt;b&gt;safe&lt;/b&gt; output",
		"&lt;img src=x onerror=alert(1)&gt;",
		"#ZgotmplZ",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("email HTML missing escaped/sanitized value %q\n---\n%s", want, html)
		}
	}
}

func TestVerifyEmailContentUsesBrandedShell(t *testing.T) {
	s := &server{cfg: &config{ServiceURL: "https://notify.example"}}
	body, err := s.verifyEmailContent("abc123")
	if err != nil {
		t.Fatalf("verifyEmailContent failed: %v", err)
	}

	if !strings.Contains(body.Text, "https://notify.example/verify?token=abc123") {
		t.Fatalf("text body missing verify URL:\n%s", body.Text)
	}
	for _, want := range []string{
		"CraftedSignal Threat Feed",
		"Confirm subscription",
		"crafted</span><span style=\"color:#0f172a;\">signal</span>",
		"https://notify.example/verify?token=abc123",
	} {
		if !strings.Contains(body.HTML, want) {
			t.Fatalf("verify HTML missing %q\n---\n%s", want, body.HTML)
		}
	}
}
