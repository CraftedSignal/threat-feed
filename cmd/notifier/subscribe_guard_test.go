package main

import (
	"net/http"
	"testing"
	"time"
)

func TestClientIPUsesRightMostForwardedAddress(t *testing.T) {
	r, err := http.NewRequest(http.MethodPost, "/subscribe", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.RemoteAddr = "203.0.113.10:443"
	r.Header.Set("X-Forwarded-For", "198.18.44.99, 2001:db8::1, 198.51.100.7")

	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("clientIP = %q; want right-most forwarded address", got)
	}
}

func TestClientIPFallsBackWhenForwardedHeaderInvalid(t *testing.T) {
	r, err := http.NewRequest(http.MethodPost, "/subscribe", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.RemoteAddr = "203.0.113.10:443"
	r.Header.Set("X-Forwarded-For", "unknown, not-an-ip")

	if got := clientIP(r); got != "203.0.113.10" {
		t.Fatalf("clientIP = %q; want RemoteAddr host", got)
	}
}

func TestSubscribeRateLimiterCapsTargetAcrossRotatedSources(t *testing.T) {
	rl := newSubscribeRateLimiter(2, time.Hour)
	target := "victim@example.com"

	if !rl.allow("198.51.100.1", target) {
		t.Fatal("first source unexpectedly rate-limited")
	}
	if !rl.allow("198.51.100.2", target) {
		t.Fatal("second source unexpectedly rate-limited")
	}
	if rl.allow("198.51.100.3", target) {
		t.Fatal("third rotated source bypassed target-wide limit")
	}
}

func TestSubscribeRateLimiterCapsSourceTargetPair(t *testing.T) {
	rl := newSubscribeRateLimiter(2, time.Hour)
	ip := "198.51.100.1"
	target := "victim@example.com"

	if !rl.allow(ip, target) {
		t.Fatal("first request unexpectedly rate-limited")
	}
	if !rl.allow(ip, target) {
		t.Fatal("second request unexpectedly rate-limited")
	}
	if rl.allow(ip, target) {
		t.Fatal("third request bypassed source-target limit")
	}
}
