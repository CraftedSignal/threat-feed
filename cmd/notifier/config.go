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

	SMTP smtpConfig
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
		SMTP: smtpConfig{
			Host:     mustEnv("SMTP_HOST"),
			Username: mustEnv("SMTP_USERNAME"),
			Password: mustEnv("SMTP_PASSWORD"),
			From:     mustEnv("SMTP_FROM"),
		},
	}

	port, err := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	if err != nil {
		return nil, fmt.Errorf("SMTP_PORT: %w", err)
	}
	cfg.SMTP.Port = port

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
