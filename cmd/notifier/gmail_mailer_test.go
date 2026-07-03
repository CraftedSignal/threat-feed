package main

import (
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
)

type fakeRawSender struct {
	users []string // captured userIDs
	raws  []string
	err   error
}

func (f *fakeRawSender) Send(userID, raw string) error {
	f.users = append(f.users, userID)
	f.raws = append(f.raws, raw)
	return f.err
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestGmailMailer_SendEncodesAndAddressesMe(t *testing.T) {
	f := &fakeRawSender{}
	m := newGmailMailerWith("CraftedSignal Threat Feed <noreply@craftedsignal.io>", f, discardLogger())
	if err := m.Send("x@example.com", "Subj", "body", ""); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.users) != 1 || f.users[0] != "me" {
		t.Fatalf("userID = %v, want [me]", f.users)
	}
	decoded, err := base64.URLEncoding.DecodeString(f.raws[0])
	if err != nil {
		t.Fatalf("raw not base64url: %v", err)
	}
	if !strings.Contains(string(decoded), "From: CraftedSignal Threat Feed <noreply@craftedsignal.io>") || !strings.Contains(string(decoded), "To: x@example.com") {
		t.Fatalf("decoded message missing headers:\n%s", decoded)
	}
}

func TestGmailMailer_SendBatchWrapsTotalFailureAsConnError(t *testing.T) {
	f := &fakeRawSender{err: errors.New("401 unauthorized_client")}
	m := newGmailMailerWith("CraftedSignal Threat Feed <noreply@craftedsignal.io>", f, discardLogger())
	errs := m.SendBatch([]SmtpMessage{{To: "a@x.com"}, {To: "b@x.com"}})
	if len(errs) != 2 {
		t.Fatalf("len(errs) = %d, want 2", len(errs))
	}
	for i, e := range errs {
		var ce *smtpConnError
		if !errors.As(e, &ce) {
			t.Fatalf("errs[%d] = %v, want *smtpConnError", i, e)
		}
	}
}
