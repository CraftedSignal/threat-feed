package main

import "testing"

func TestLoadConfig_GmailBackendSkipsSMTPCreds(t *testing.T) {
	base := map[string]string{
		"PROJECT_ID": "p", "SITE_ORIGIN": "https://s", "DISPATCH_TOKEN": "t",
		"SMTP_FROM": "CraftedSignal Threat Feed <noreply@craftedsignal.io>", "MAILER_BACKEND": "gmail",
		"GMAIL_SUBJECT": "nhofmans@craftedsignal.io",
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig (gmail, no SMTP creds set): %v", err)
	}
	if cfg.MailerBackend != "gmail" || cfg.Gmail.Subject != "nhofmans@craftedsignal.io" {
		t.Fatalf("unexpected cfg: backend=%q subject=%q", cfg.MailerBackend, cfg.Gmail.Subject)
	}
	if cfg.SMTP.From != "CraftedSignal Threat Feed <noreply@craftedsignal.io>" {
		t.Fatalf("SMTP.From = %q", cfg.SMTP.From)
	}
}
