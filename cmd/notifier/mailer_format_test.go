package main

import (
	"strings"
	"testing"
)

func TestBuildRFC822_PlainAndMultipart(t *testing.T) {
	plain := buildRFC822("CraftedSignal Threat Feed <noreply@craftedsignal.io>", SmtpMessage{To: "a@example.com", Subject: "Hi", TextBody: "hello"})
	for _, want := range []string{"From: CraftedSignal Threat Feed <noreply@craftedsignal.io>", "To: a@example.com", "Subject: Hi", "text/plain; charset=utf-8", "hello"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("plain message missing %q\n---\n%s", want, plain)
		}
	}
	multi := buildRFC822("CraftedSignal Threat Feed <noreply@craftedsignal.io>", SmtpMessage{To: "b@example.com", Subject: "Hey", TextBody: "t", HTMLBody: "<b>h</b>"})
	for _, want := range []string{`multipart/alternative; boundary="`, "text/plain; charset=utf-8", "text/html; charset=utf-8"} {
		if !strings.Contains(multi, want) {
			t.Fatalf("multipart message missing %q\n---\n%s", want, multi)
		}
	}
}

func TestEnvelopeFromStripsDisplayName(t *testing.T) {
	got := envelopeFrom("CraftedSignal Threat Feed <noreply@craftedsignal.io>")
	if got != "noreply@craftedsignal.io" {
		t.Fatalf("envelopeFrom = %q, want noreply@craftedsignal.io", got)
	}
}
