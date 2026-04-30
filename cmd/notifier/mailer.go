package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

// hashEmail returns a stable, non-reversible identifier for an email
// address. Used in error logs so we can correlate failures without
// persisting plaintext addresses to log storage.
func hashEmail(addr string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(addr))))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

type mailer interface {
	Send(to, subject, body string) error
	// SendBatch delivers a slice of (to, subject, body) triples over a
	// single SMTP connection + AUTH, instead of one connection per
	// recipient. Materially cuts auth-rate against Workspace's relay
	// (~50 logins per IP per N-min) when the periodic flush drains
	// many subscribers' queues at once.
	//
	// Returns a slice of per-recipient errors (nil = delivered). Length
	// always matches len(messages); a single hard failure (dial / TLS /
	// AUTH) populates every slot with the same error so callers don't
	// have to special-case the all-failed path.
	SendBatch(messages []SmtpMessage) []error
}

// SmtpMessage carries the per-recipient bits of one delivery. Body is
// the full RFC822 message body the caller already assembled.
type SmtpMessage struct {
	To      string
	Subject string
	Body    string
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
		m.logger.Error("smtp send failed", "to_hash", hashEmail(to), "err", err)
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

// SendBatch opens one SMTP+STARTTLS+AUTH session and reuses it across
// every message in the batch, issuing MAIL/RCPT/DATA per recipient.
// Returns a per-recipient error slice. Hard connection / TLS / AUTH
// failures fan the same error across every slot so callers can treat
// the slice as authoritative without checking a separate flag.
func (m *smtpMailer) SendBatch(messages []SmtpMessage) []error {
	out := make([]error, len(messages))
	if len(messages) == 0 {
		return out
	}
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)

	conn, err := smtp.Dial(addr)
	if err != nil {
		m.logger.Error("smtp dial failed", "host", m.cfg.Host, "err", err)
		fillAll(out, fmt.Errorf("smtp dial: %w", err))
		return out
	}
	defer func() { _ = conn.Close() }()

	tlsCfg := &tls.Config{
		ServerName: m.cfg.Host,
		MinVersion: tls.VersionTLS12,
	}
	if err := conn.StartTLS(tlsCfg); err != nil {
		m.logger.Error("smtp starttls failed", "err", err)
		fillAll(out, fmt.Errorf("starttls: %w", err))
		return out
	}

	auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	if err := conn.Auth(auth); err != nil {
		m.logger.Error("smtp auth failed", "err", err)
		fillAll(out, fmt.Errorf("auth: %w", err))
		return out
	}

	for i, msg := range messages {
		if err := m.sendOne(conn, msg); err != nil {
			m.logger.Error("smtp send failed", "to_hash", hashEmail(msg.To), "err", err)
			out[i] = err
			// Some servers reset MAIL FROM state after a hard error.
			// RSET to be safe; ignore failure.
			_ = conn.Reset()
			continue
		}
	}
	_ = conn.Quit()
	return out
}

// fillAll populates every slot of errs with the same error. Used when a
// connection-level failure means none of the recipients can be retried
// without first re-establishing the session.
func fillAll(errs []error, err error) {
	for i := range errs {
		errs[i] = err
	}
}

// sendOne issues MAIL FROM / RCPT TO / DATA on an already-authenticated
// SMTP client connection.
func (m *smtpMailer) sendOne(conn *smtp.Client, msg SmtpMessage) error {
	if err := conn.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := conn.Rcpt(msg.To); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	w, err := conn.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	headers := map[string]string{
		"From":         m.cfg.From,
		"To":           msg.To,
		"Subject":      msg.Subject,
		"MIME-Version": "1.0",
		"Content-Type": "text/plain; charset=utf-8",
	}
	var body strings.Builder
	for k, v := range headers {
		body.WriteString(k)
		body.WriteString(": ")
		body.WriteString(v)
		body.WriteString("\r\n")
	}
	body.WriteString("\r\n")
	body.WriteString(msg.Body)
	if _, err := w.Write([]byte(body.String())); err != nil {
		_ = w.Close()
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close DATA: %w", err)
	}
	return nil
}
