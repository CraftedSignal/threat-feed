package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeSubStore struct {
	saveErr error
	saved   int
	deleted int
}

func (f *fakeSubStore) CreatePending(context.Context, string, Subscription) error { return nil }
func (f *fakeSubStore) ConsumePending(context.Context, string) (Subscription, error) {
	return Subscription{}, errors.New("not used")
}
func (f *fakeSubStore) SaveSubscription(context.Context, Subscription) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved++
	return nil
}
func (f *fakeSubStore) DeleteVerifiedByEmail(context.Context, string, Channel) (int, error) {
	return 0, nil
}
func (f *fakeSubStore) DeleteByUnsubscribeToken(context.Context, string) error {
	f.deleted++
	return nil
}

func subscribeWebhook(t *testing.T, store *fakeSubStore, welcome func(Channel, string, string) error) (int, string) {
	t.Helper()
	var logs bytes.Buffer
	srv := &server{
		cfg:         &config{},
		store:       store,
		logger:      slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		rateLimiter: newSubscribeRateLimiter(100, time.Hour),
		sendWelcome: welcome,
	}
	body := `{"channel":"slack","webhook_url":"https://hooks.slack.com/services/T0/B0/x"}`
	req := httptest.NewRequest(http.MethodPost, "/subscribe", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleSubscribe(rec, req)
	return rec.Code, logs.String()
}

func TestSubscribeWebhookVerificationStatusMapping(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantCode  int
		wantLevel string
	}{
		{"blocked ip", fmt.Errorf("webhook request failed: %w", &blockedWebhookIPError{IP: net.ParseIP("169.254.169.254")}), 400, "level=WARN"},
		{"invalid url", &invalidWebhookURLError{Err: errors.New("HTTPS is required")}, 400, "level=WARN"},
		{"unreachable", &unreachableWebhookError{Err: errors.New("no such host")}, 422, "level=WARN"},
		{"non-2xx", &webhookStatusError{Code: 404}, 422, "level=WARN"},
		{"unexpected", errors.New("boom"), 502, "level=ERROR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeSubStore{}
			code, logs := subscribeWebhook(t, store, func(Channel, string, string) error { return tc.err })
			if code != tc.wantCode {
				t.Fatalf("status = %d; want %d", code, tc.wantCode)
			}
			if !strings.Contains(logs, tc.wantLevel) || !strings.Contains(logs, "webhook verification failed") {
				t.Fatalf("logs = %q; want %s", logs, tc.wantLevel)
			}
			if tc.wantLevel == "level=WARN" && strings.Contains(logs, "level=ERROR") {
				t.Fatalf("client error logged at ERROR: %q", logs)
			}
			if store.deleted != 1 {
				t.Fatalf("subscription not rolled back")
			}
		})
	}
}

func TestSubscribeWebhookSuccessAndStorageFailure(t *testing.T) {
	store := &fakeSubStore{}
	if code, _ := subscribeWebhook(t, store, func(Channel, string, string) error { return nil }); code != http.StatusAccepted {
		t.Fatalf("valid webhook status = %d; want 202", code)
	}
	store = &fakeSubStore{saveErr: errors.New("firestore down")}
	if code, _ := subscribeWebhook(t, store, func(Channel, string, string) error { return nil }); code != http.StatusInternalServerError {
		t.Fatalf("storage failure status = %d; want 500", code)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func withWebhookTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	old := webhookClient
	webhookClient = &http.Client{Transport: rt, Timeout: 5 * time.Second}
	t.Cleanup(func() { webhookClient = old })
}

func TestPostWebhookJSONReturnsTypedErrors(t *testing.T) {
	const hook = "https://hooks.slack.com/services/T0/B0/x"

	t.Run("blocked ip via real dialer", func(t *testing.T) {
		d := safeWebhookDialContext(&net.Dialer{}, func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
		})
		withWebhookTransport(t, &http.Transport{DialContext: d})
		var be *blockedWebhookIPError
		if err := postWebhookJSON(ChannelSlack, hook, map[string]any{}); !errors.As(err, &be) {
			t.Fatalf("err = %v; want blockedWebhookIPError", err)
		}
	})
	t.Run("invalid url", func(t *testing.T) {
		var ie *invalidWebhookURLError
		if err := postWebhookJSON(ChannelSlack, "http://hooks.slack.com/x", map[string]any{}); !errors.As(err, &ie) {
			t.Fatalf("err = %v; want invalidWebhookURLError", err)
		}
	})
	t.Run("404", func(t *testing.T) {
		withWebhookTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("no_service"))}, nil
		}))
		var se *webhookStatusError
		if err := postWebhookJSON(ChannelSlack, hook, map[string]any{}); !errors.As(err, &se) || se.Code != 404 {
			t.Fatalf("err = %v; want webhookStatusError 404", err)
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		withWebhookTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp: connection refused")
		}))
		// non-retryable text avoids the retry sleeps
		withWebhookTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("tls: handshake failure")
		}))
		var ue *unreachableWebhookError
		if err := postWebhookJSON(ChannelSlack, hook, map[string]any{}); !errors.As(err, &ue) {
			t.Fatalf("err = %v; want unreachableWebhookError", err)
		}
	})
}
