package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

type mailer interface {
	Send(to, subject, body string) error
}

type smtpMailer struct {
	cfg    smtpConfig
	logger *slog.Logger
}

func newSMTPMailer(cfg smtpConfig, logger *slog.Logger) *smtpMailer {
	return &smtpMailer{cfg: cfg, logger: logger}
}

// Send dispatches a single plaintext email via SMTP+STARTTLS. Used for
// verification links, unsubscribe confirmations, and per-brief notices.
func (m *smtpMailer) Send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)

	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)

	headers := map[string]string{
		"From":         m.cfg.From,
		"To":           to,
		"Subject":      subject,
		"MIME-Version": "1.0",
		"Content-Type": "text/plain; charset=utf-8",
	}
	var msg strings.Builder
	for k, v := range headers {
		msg.WriteString(k)
		msg.WriteString(": ")
		msg.WriteString(v)
		msg.WriteString("\r\n")
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)

	// Workspace SMTP relay supports STARTTLS on 587. The stdlib helper
	// does the right thing — but it doesn't expose tls.Config tuning;
	// good enough for this use case.
	tlsCfg := &tls.Config{
		ServerName: m.cfg.Host,
		MinVersion: tls.VersionTLS12,
	}
	_ = tlsCfg // reserved for explicit dial if we ever switch to net.Dial+tls.Client

	if err := smtp.SendMail(addr, auth, m.cfg.From, []string{to}, []byte(msg.String())); err != nil {
		m.logger.Error("smtp send failed", "to", to, "err", err)
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}
