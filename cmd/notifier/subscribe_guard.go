package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// subscribeRateLimiter provides per-IP and per-target rate limiting for
// the public /subscribe endpoint. It uses a simple in-memory token bucket
// with periodic cleanup. Limits are intentionally conservative for a
// low-volume subscription service.
type subscribeRateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*rateBucket
	limit     int
	window    time.Duration
	cleanupAt time.Time
}

type rateBucket struct {
	tokens int
	reset  time.Time
}

func newSubscribeRateLimiter(limit int, window time.Duration) *subscribeRateLimiter {
	return &subscribeRateLimiter{
		buckets: make(map[string]*rateBucket),
		limit:   limit,
		window:  window,
	}
}

// key returns a composite key for the given source IP and target (email or
// webhook URL). This prevents a single actor from spraying many targets and
// also prevents a single target from being flooded by many sources behind a
// proxy (limited effectiveness, but better than nothing without authenticated
// clients).
func (rl *subscribeRateLimiter) key(ip, target string) string {
	return ip + "|" + target
}

func (rl *subscribeRateLimiter) allow(ip, target string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if time.Since(rl.cleanupAt) > rl.window {
		rl.cleanup()
	}

	k := rl.key(ip, target)
	now := time.Now()
	b, ok := rl.buckets[k]
	if !ok || now.After(b.reset) {
		rl.buckets[k] = &rateBucket{tokens: rl.limit - 1, reset: now.Add(rl.window)}
		return true
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

func (rl *subscribeRateLimiter) cleanup() {
	now := time.Now()
	for k, b := range rl.buckets {
		if now.After(b.reset) {
			delete(rl.buckets, k)
		}
	}
	rl.cleanupAt = now
}

// clientIP returns the most immediate untrusted client IP from r. It prefers
// X-Forwarded-For when behind a load balancer, but falls back to r.RemoteAddr.
// Cloud Run sets X-Forwarded-For reliably.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// recaptchaResponse is the subset of Google's reCAPTCHA API response we care
// about.
type recaptchaResponse struct {
	Success    bool     `json:"success"`
	Score      float64  `json:"score"`
	Action     string   `json:"action"`
	ErrorCodes []string `json:"error-codes"`
}

// verifyRecaptcha validates a reCAPTCHA token with Google. It returns nil if
// the token is valid or if no secret is configured (validation disabled).
func verifyRecaptcha(ctx context.Context, client *http.Client, secret, token string) error {
	if secret == "" {
		return nil
	}
	if token == "" {
		return fmt.Errorf("missing recaptcha token")
	}
	if client == nil {
		client = http.DefaultClient
	}

	form := url.Values{}
	form.Set("secret", secret)
	form.Set("response", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://www.google.com/recaptcha/api/siteverify", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("recaptcha verify request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("recaptcha verify read: %w", err)
	}

	var result recaptchaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("recaptcha verify decode: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("recaptcha verify failed: %v", result.ErrorCodes)
	}
	return nil
}
