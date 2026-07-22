package main

import (
	"fmt"
	"os"
	"strconv"
)

type config struct {
	ProjectID   string
	Environment string
	SiteOrigin  string
	ServiceURL  string // self URL (Cloud Run); used in verify/unsub email links

	DispatchToken      string // authorizes /dispatch
	DispatchFlushToken string // authorizes /flush-pending; falls back to DispatchToken if unset

	RecaptchaSecret string // Google reCAPTCHA v2/v3 secret; empty disables validation

	MailerBackend string // "gmail" (default) or "smtp"
	Gmail         gmailConfig
	SMTP          smtpConfig
}

type gmailConfig struct {
	Subject string // DWD-impersonated Workspace user (real mailbox; From: uses SMTP.From alias)
}

type smtpConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

func loadConfig() (*config, error) {
	projectID, err := mustEnv("PROJECT_ID")
	if err != nil {
		return nil, err
	}
	siteOrigin, err := mustEnv("SITE_ORIGIN")
	if err != nil {
		return nil, err
	}
	dispatchToken, err := mustEnv("DISPATCH_TOKEN")
	if err != nil {
		return nil, err
	}
	smtpFrom, err := mustEnv("SMTP_FROM")
	if err != nil {
		return nil, err
	}

	cfg := &config{
		ProjectID:          projectID,
		Environment:        getEnv("ENVIRONMENT", "dev"),
		SiteOrigin:         siteOrigin,
		ServiceURL:         getEnv("SERVICE_URL", ""), // optional; set after first deploy
		DispatchToken:      dispatchToken,
		DispatchFlushToken: getEnv("DISPATCH_FLUSH_TOKEN", ""),
		RecaptchaSecret:    getEnv("RECAPTCHA_SECRET", ""),
		MailerBackend:      getEnv("MAILER_BACKEND", "gmail"),
		SMTP: smtpConfig{
			From: smtpFrom, // From: header for both backends
		},
	}

	switch cfg.MailerBackend {
	case "gmail":
		subject, err := mustEnv("GMAIL_SUBJECT")
		if err != nil {
			return nil, err
		}
		cfg.Gmail.Subject = subject
	case "smtp":
		host, err := mustEnv("SMTP_HOST")
		if err != nil {
			return nil, err
		}
		username, err := mustEnv("SMTP_USERNAME")
		if err != nil {
			return nil, err
		}
		password, err := mustEnv("SMTP_PASSWORD")
		if err != nil {
			return nil, err
		}
		cfg.SMTP.Host = host
		cfg.SMTP.Username = username
		cfg.SMTP.Password = password
		port, err := strconv.Atoi(getEnv("SMTP_PORT", "587"))
		if err != nil {
			return nil, fmt.Errorf("SMTP_PORT: %w", err)
		}
		cfg.SMTP.Port = port
	default:
		return nil, fmt.Errorf("MAILER_BACKEND must be gmail or smtp, got %q", cfg.MailerBackend)
	}

	if cfg.DispatchFlushToken == "" {
		cfg.DispatchFlushToken = cfg.DispatchToken
	}

	return cfg, nil
}

func mustEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("required env %s is empty", key)
	}
	return v, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
