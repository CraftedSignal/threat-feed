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

// subscribeRateLimiter provides source-target and target-wide rate limiting
// for the public /subscribe endpoint. It uses a simple in-memory token bucket
// with periodic cleanup. Limits are intentionally conservative for a low-volume
// subscription service.
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

func (rl *subscribeRateLimiter) sourceTargetKey(ip, target string) string {
	return "source_target|" + ip + "|" + target
}

func (rl *subscribeRateLimiter) targetKey(target string) string {
	return "target|" + target
}

func (rl *subscribeRateLimiter) allow(ip, target string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if time.Since(rl.cleanupAt) > rl.window {
		rl.cleanup()
	}

	now := time.Now()

	keys := []string{rl.sourceTargetKey(ip, target)}
	if target != "" {
		keys = append(keys, rl.targetKey(target))
	}

	for _, key := range keys {
		if !rl.available(now, key) {
			return false
		}
	}

	for _, key := range keys {
		rl.consume(now, key)
	}
	return true
}

func (rl *subscribeRateLimiter) available(now time.Time, key string) bool {
	b, ok := rl.buckets[key]
	return !ok || now.After(b.reset) || b.tokens > 0
}

func (rl *subscribeRateLimiter) consume(now time.Time, key string) {
	b, ok := rl.buckets[key]
	if !ok || now.After(b.reset) {
		b = &rateBucket{tokens: rl.limit - 1, reset: now.Add(rl.window)}
		rl.buckets[key] = b
		return
	}
	b.tokens--
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

// clientIP returns the most immediate untrusted client IP from r. Cloud Run and
// the load balancer append their view of the client to X-Forwarded-For, so use
// the right-most valid address instead of trusting a caller-supplied left-most
// element. Fall back to r.RemoteAddr when X-Forwarded-For is absent or invalid.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if ip := net.ParseIP(strings.TrimSpace(parts[i])); ip != nil {
				return ip.String()
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String()
	}
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
	defer func() {
		_ = resp.Body.Close()
	}()

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
