package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestValidateWebhookURL(t *testing.T) {
	valid := []struct {
		name    string
		channel Channel
		raw     string
		want    string
	}{
		{
			name:    "slack services URL",
			channel: ChannelSlack,
			raw:     " https://HOOKS.SLACK.COM:443/services/T000/B000/token ",
			want:    "https://hooks.slack.com/services/T000/B000/token",
		},
		{
			name:    "teams outlook URL",
			channel: ChannelTeams,
			raw:     "https://outlook.office.com/webhook/abc/IncomingWebhook/def",
			want:    "https://outlook.office.com/webhook/abc/IncomingWebhook/def",
		},
		{
			name:    "teams office connector URL",
			channel: ChannelTeams,
			raw:     "https://tenant.webhook.office.com/webhookb2/abc/IncomingWebhook/def",
			want:    "https://tenant.webhook.office.com/webhookb2/abc/IncomingWebhook/def",
		},
		{
			name:    "teams logic app URL",
			channel: ChannelTeams,
			raw:     "https://prod-00.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke",
			want:    "https://prod-00.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke",
		},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateWebhookURL(tc.raw, tc.channel)
			if err != nil {
				t.Fatalf("validateWebhookURL returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("validateWebhookURL = %q; want %q", got, tc.want)
			}
		})
	}

	invalid := []struct {
		name    string
		channel Channel
		raw     string
	}{
		{"slack http", ChannelSlack, "http://hooks.slack.com/services/T/B/token"},
		{"slack suffix host", ChannelSlack, "https://hooks.slack.com.evil.test/services/T/B/token"},
		{"slack userinfo", ChannelSlack, "https://hooks.slack.com@evil.test/services/T/B/token"},
		{"slack wrong path", ChannelSlack, "https://hooks.slack.com/api/chat.postMessage"},
		{"slack bad port", ChannelSlack, "https://hooks.slack.com:8443/services/T/B/token"},
		{"teams substring host bypass", ChannelTeams, "https://evil.test/path?next=outlook.office.com/webhook"},
		{"teams IP host", ChannelTeams, "https://127.0.0.1/webhook/abc"},
		{"teams wrong path", ChannelTeams, "https://outlook.office.com/not-webhook/abc"},
		{"teams bad port", ChannelTeams, "https://outlook.office.com:8443/webhook/abc"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := validateWebhookURL(tc.raw, tc.channel); err == nil {
				t.Fatalf("validateWebhookURL = %q, nil error; want error", got)
			}
		})
	}
}

func TestSubscribeRequestUsesWebhookValidation(t *testing.T) {
	sub, err := subscribeRequest{
		Channel:    "slack",
		WebhookURL: " https://HOOKS.SLACK.COM:443/services/T000/B000/token ",
	}.toSubscription()
	if err != nil {
		t.Fatalf("toSubscription returned error: %v", err)
	}
	if sub.WebhookURL != "https://hooks.slack.com/services/T000/B000/token" {
		t.Fatalf("WebhookURL = %q", sub.WebhookURL)
	}

	_, err = subscribeRequest{
		Channel:    "teams",
		WebhookURL: "https://evil.test/path?next=outlook.office.com/webhook",
	}.toSubscription()
	if err == nil {
		t.Fatal("toSubscription accepted Teams substring bypass URL")
	}
}

func TestIsBlockedWebhookIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.0.1", true},
		{"fc00::1", true},
		{"169.254.1.1", true},
		{"100.64.0.1", true},
		{"198.18.0.1", true},
		{"192.0.2.1", true},
		{"64:ff9b::808:808", true},
		{"8.8.8.8", false},
		{"2606:4700:4700::1111", false},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			got := isBlockedWebhookIP(net.ParseIP(tc.ip))
			if got != tc.blocked {
				t.Fatalf("isBlockedWebhookIP(%s) = %v; want %v", tc.ip, got, tc.blocked)
			}
		})
	}
}

func TestSafeWebhookDialContextRejectsUnsafeDNS(t *testing.T) {
	tests := []struct {
		name string
		ips  []net.IPAddr
	}{
		{
			name: "private",
			ips:  []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}},
		},
		{
			name: "mixed public and private",
			ips: []net.IPAddr{
				{IP: net.ParseIP("8.8.8.8")},
				{IP: net.ParseIP("10.0.0.1")},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dial := safeWebhookDialContext(
				&net.Dialer{Timeout: time.Millisecond},
				func(context.Context, string) ([]net.IPAddr, error) { return tc.ips, nil },
			)
			conn, err := dial(context.Background(), "tcp", "hooks.slack.com:443")
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil {
				t.Fatal("safeWebhookDialContext accepted unsafe DNS answer")
			}
			if !strings.Contains(err.Error(), "blocked IP") {
				t.Fatalf("error = %q; want blocked IP", err.Error())
			}
		})
	}
}
