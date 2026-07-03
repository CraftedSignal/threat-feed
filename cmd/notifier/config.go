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

	DispatchToken string

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
	cfg := &config{
		ProjectID:     mustEnv("PROJECT_ID"),
		Environment:   getEnv("ENVIRONMENT", "dev"),
		SiteOrigin:    mustEnv("SITE_ORIGIN"),
		ServiceURL:    getEnv("SERVICE_URL", ""), // optional; set after first deploy
		DispatchToken: mustEnv("DISPATCH_TOKEN"),
		MailerBackend: getEnv("MAILER_BACKEND", "gmail"),
		SMTP: smtpConfig{
			From: mustEnv("SMTP_FROM"), // From: header for both backends
		},
	}

	switch cfg.MailerBackend {
	case "gmail":
		cfg.Gmail.Subject = mustEnv("GMAIL_SUBJECT")
	case "smtp":
		cfg.SMTP.Host = mustEnv("SMTP_HOST")
		cfg.SMTP.Username = mustEnv("SMTP_USERNAME")
		cfg.SMTP.Password = mustEnv("SMTP_PASSWORD")
		port, err := strconv.Atoi(getEnv("SMTP_PORT", "587"))
		if err != nil {
			return nil, fmt.Errorf("SMTP_PORT: %w", err)
		}
		cfg.SMTP.Port = port
	default:
		return nil, fmt.Errorf("MAILER_BACKEND must be gmail or smtp, got %q", cfg.MailerBackend)
	}

	return cfg, nil
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("required env %s is empty", key))
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
