package main

import (
	"strings"
	"testing"
)

func TestBuildRFC822_PlainAndMultipart(t *testing.T) {
	plain, err := buildRFC822("CraftedSignal Threat Feed <noreply@craftedsignal.io>", SmtpMessage{To: "a@example.com", Subject: "Hi", TextBody: "hello"})
	if err != nil {
		t.Fatalf("buildRFC822 plain: %v", err)
	}
	for _, want := range []string{`From: "CraftedSignal Threat Feed" <noreply@craftedsignal.io>`, "To: <a@example.com>", "Subject: Hi", "text/plain; charset=utf-8", "hello"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("plain message missing %q\n---\n%s", want, plain)
		}
	}
	multi, err := buildRFC822("CraftedSignal Threat Feed <noreply@craftedsignal.io>", SmtpMessage{To: "b@example.com", Subject: "Hey", TextBody: "t", HTMLBody: "<b>h</b>"})
	if err != nil {
		t.Fatalf("buildRFC822 multipart: %v", err)
	}
	for _, want := range []string{`multipart/alternative; boundary="`, "text/plain; charset=utf-8", "text/html; charset=utf-8"} {
		if !strings.Contains(multi, want) {
			t.Fatalf("multipart message missing %q\n---\n%s", want, multi)
		}
	}
}

func TestEnvelopeFromStripsDisplayName(t *testing.T) {
	got, err := envelopeFrom("CraftedSignal Threat Feed <noreply@craftedsignal.io>")
	if err != nil {
		t.Fatalf("envelopeFrom: %v", err)
	}
	if got != "noreply@craftedsignal.io" {
		t.Fatalf("envelopeFrom = %q, want noreply@craftedsignal.io", got)
	}
}

func TestBuildRFC822RejectsAddressInjection(t *testing.T) {
	_, err := buildRFC822(
		"CraftedSignal Threat Feed <noreply@craftedsignal.io>",
		SmtpMessage{To: "victim@example.com\r\nBcc: attacker@example.com", Subject: "Hi", TextBody: "hello"},
	)
	if err == nil {
		t.Fatal("buildRFC822 accepted recipient header injection")
	}
}

func TestBuildRFC822SanitizesSubjectInjection(t *testing.T) {
	msg, err := buildRFC822(
		"CraftedSignal Threat Feed <noreply@craftedsignal.io>",
		SmtpMessage{To: "victim@example.com", Subject: "Hi\r\nBcc: attacker@example.com", TextBody: "hello"},
	)
	if err != nil {
		t.Fatalf("buildRFC822: %v", err)
	}
	headers := strings.SplitN(msg, "\r\n\r\n", 2)[0]
	if strings.Contains(headers, "\r\nBcc:") {
		t.Fatalf("subject injected a Bcc header:\n%s", headers)
	}
}
