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
			name:    "slack compatible external URL",
			channel: ChannelSlack,
			raw:     " https://WEBHOOKS.EXAMPLE.COM:443/services/T000/B000/token?x=1 ",
			want:    "https://webhooks.example.com/services/T000/B000/token?x=1",
		},
		{
			name:    "teams compatible external URL with custom port",
			channel: ChannelTeams,
			raw:     "https://tenant.webhook.office.com:8443/webhook/abc/IncomingWebhook/def",
			want:    "https://tenant.webhook.office.com:8443/webhook/abc/IncomingWebhook/def",
		},
		{
			name:    "external IPv4 literal",
			channel: ChannelSlack,
			raw:     "https://8.8.8.8/hook",
			want:    "https://8.8.8.8/hook",
		},
		{
			name:    "external IPv6 literal",
			channel: ChannelTeams,
			raw:     "https://[2606:4700:4700::1111]:443/hook",
			want:    "https://[2606:4700:4700::1111]/hook",
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
		{"http scheme", ChannelSlack, "http://webhooks.example.com/services/T/B/token"},
		{"userinfo", ChannelSlack, "https://webhooks.example.com@evil.com/services/T/B/token"},
		{"fragment", ChannelSlack, "https://webhooks.example.com/services/T/B/token#frag"},
		{"bad port", ChannelSlack, "https://webhooks.example.com:70000/services/T/B/token"},
		{"loopback IPv4 host", ChannelTeams, "https://127.0.0.1/webhook/abc"},
		{"private IPv4 host", ChannelTeams, "https://10.0.0.1/webhook/abc"},
		{"documentation IPv4 host", ChannelTeams, "https://192.0.2.1/webhook/abc"},
		{"link local IPv6 host", ChannelTeams, "https://[fe80::1]/webhook/abc"},
		{"IPv6 zone host", ChannelTeams, "https://[fe80::1%25lo0]/webhook/abc"},
		{"single-label DNS host", ChannelTeams, "https://localhost/webhook/abc"},
		{"reserved test DNS host", ChannelTeams, "https://evil.test/webhook/abc"},
		{"invalid channel", ChannelEmail, "https://webhooks.example.com/webhook/abc"},
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
		WebhookURL: " https://WEBHOOKS.EXAMPLE.COM:443/services/T000/B000/token ",
	}.toSubscription()
	if err != nil {
		t.Fatalf("toSubscription returned error: %v", err)
	}
	if sub.WebhookURL != "https://webhooks.example.com/services/T000/B000/token" {
		t.Fatalf("WebhookURL = %q", sub.WebhookURL)
	}

	_, err = subscribeRequest{
		Channel:    "teams",
		WebhookURL: "https://127.0.0.1/path?next=outlook.office.com/webhook",
	}.toSubscription()
	if err == nil {
		t.Fatal("toSubscription accepted internal webhook URL")
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

func TestSafeWebhookDialContextRejectsUnsafeLiteralAddress(t *testing.T) {
	dial := safeWebhookDialContext(
		&net.Dialer{Timeout: time.Millisecond},
		func(context.Context, string) ([]net.IPAddr, error) {
			t.Fatal("lookup must not be called for IP literal addresses")
			return nil, nil
		},
	)
	conn, err := dial(context.Background(), "tcp", "127.0.0.1:443")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("safeWebhookDialContext accepted unsafe literal address")
	}
	if !strings.Contains(err.Error(), "blocked IP") {
		t.Fatalf("error = %q; want blocked IP", err.Error())
	}
}

func TestSafeWebhookDialContextResolvesEveryDial(t *testing.T) {
	calls := 0
	dial := safeWebhookDialContext(
		&net.Dialer{Timeout: time.Millisecond},
		func(context.Context, string) ([]net.IPAddr, error) {
			calls++
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	)
	for i := 0; i < 2; i++ {
		conn, err := dial(context.Background(), "tcp", "webhooks.example.com:443")
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			t.Fatal("safeWebhookDialContext accepted unsafe DNS answer")
		}
	}
	if calls != 2 {
		t.Fatalf("lookup calls = %d; want 2", calls)
	}
}
