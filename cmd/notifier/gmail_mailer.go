package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"cloud.google.com/go/compute/metadata"
	gmail "google.golang.org/api/gmail/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// rawSender abstracts the Gmail "send a raw RFC822 message" call so
// gmailMailer's build/encode/error logic is unit-testable without live API.
type rawSender interface {
	Send(userID, raw string) error
}

// gmailMailer implements mailer over the Gmail API. It builds the same
// RFC822 message the SMTP path did and submits it as a base64url Raw body.
type gmailMailer struct {
	from   string // From: header (the noreply@ alias)
	userID string // Gmail userId; "me" = the impersonated DWD subject
	sender rawSender
	logger *slog.Logger
}

func newGmailMailerWith(from string, sender rawSender, logger *slog.Logger) *gmailMailer {
	return &gmailMailer{from: from, userID: "me", sender: sender, logger: logger}
}

func encodeRaw(rfc822 string) string {
	return base64.URLEncoding.EncodeToString([]byte(rfc822))
}

func (m *gmailMailer) Send(to, subject, textBody, htmlBody string) error {
	raw := encodeRaw(buildRFC822(m.from, SmtpMessage{To: to, Subject: subject, TextBody: textBody, HTMLBody: htmlBody}))
	if err := m.sender.Send(m.userID, raw); err != nil {
		m.logger.Error("gmail send failed", "to_hash", hashEmail(to), "err", err)
		return fmt.Errorf("gmail send: %w", err)
	}
	return nil
}

// SendBatch sends each message with its own API call. Every failure is
// wrapped as *smtpConnError so the dispatcher's existing "all failed ->
// back off" logic still triggers when auth/quota knocks out the whole batch.
func (m *gmailMailer) SendBatch(messages []SmtpMessage) []error {
	out := make([]error, len(messages))
	for i, msg := range messages {
		raw := encodeRaw(buildRFC822(m.from, msg))
		if err := m.sender.Send(m.userID, raw); err != nil {
			m.logger.Error("gmail send failed", "to_hash", hashEmail(msg.To), "err", err)
			out[i] = &smtpConnError{err: fmt.Errorf("gmail send: %w", err)}
		}
	}
	return out
}

// gmailAPISender is the production rawSender backed by a live Gmail service.
type gmailAPISender struct{ svc *gmail.Service }

func (s *gmailAPISender) Send(userID, raw string) error {
	_, err := s.svc.Users.Messages.Send(userID, &gmail.Message{Raw: raw}).Do()
	return err
}

// newGmailMailer builds a gmailMailer using keyless domain-wide delegation:
// the Cloud Run runtime SA (discovered from the metadata server) impersonates
// itself with a DWD Subject, signing via the IAM Credentials API — no key.
func newGmailMailer(ctx context.Context, cfg *config, logger *slog.Logger) (*gmailMailer, error) {
	saEmail, err := metadata.EmailWithContext(ctx, "default")
	if err != nil {
		return nil, fmt.Errorf("discover runtime service account: %w", err)
	}
	ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: saEmail,
		Scopes:          []string{gmail.GmailSendScope},
		Subject:         cfg.Gmail.Subject,
	})
	if err != nil {
		return nil, fmt.Errorf("build delegated token source: %w", err)
	}
	svc, err := gmail.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		return nil, fmt.Errorf("gmail service: %w", err)
	}
	logger.Info("gmail mailer ready", "delegate_sa", saEmail, "subject", cfg.Gmail.Subject, "from", cfg.SMTP.From)
	return newGmailMailerWith(cfg.SMTP.From, &gmailAPISender{svc: svc}, logger), nil
}
