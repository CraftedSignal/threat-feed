package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestWebhookRetriesTypedTimeout(t *testing.T) {
	const hook = "https://outlook.office.com/webhook/private-token"
	calls := 0
	withWebhookTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return nil, context.DeadlineExceeded
		}
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	}))
	if err := postWebhookJSON(ChannelTeams, hook, map[string]string{"text": "test"}); err != nil {
		t.Fatalf("transient timeout was not recovered: %v", err)
	}
	if calls != 2 {
		t.Fatalf("attempts = %d, want 2", calls)
	}
}

func TestWebhookErrorsNeverExposeSecretTargetOrResponse(t *testing.T) {
	const hook = "https://outlook.office.com/webhook/private-token?sig=private-signature"
	for _, err := range []error{
		&unreachableWebhookError{Err: &url.Error{Op: "Post", URL: hook, Err: context.DeadlineExceeded}},
		&invalidWebhookURLError{Err: &url.Error{Op: "parse", URL: hook, Err: errors.New("invalid control character")}},
		&webhookStatusError{Code: http.StatusTooManyRequests, Body: "target=" + hook},
	} {
		for _, secret := range []string{"private-token", "private-signature"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%T exposes webhook secret: %s", err, err.Error())
			}
		}
	}
}

func TestWebhookTerminalClientStatusIsNotRetried(t *testing.T) {
	oldDelays := webhookRetryDelays
	webhookRetryDelays = []time.Duration{0, 0}
	t.Cleanup(func() { webhookRetryDelays = oldDelays })
	calls := 0
	withWebhookTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("private"))}, nil
	}))
	err := postWebhookJSON(ChannelTeams, "https://outlook.office.com/webhook/private-token", map[string]string{"text": "test"})
	var statusErr *webhookStatusError
	if !errors.As(err, &statusErr) || statusErr.Code != http.StatusNotFound {
		t.Fatalf("error = %v, want typed 404", err)
	}
	if calls != 1 {
		t.Fatalf("attempts = %d, want terminal 404 to stop after one", calls)
	}
}

func TestWebhookRetryWaitHonorsCancellation(t *testing.T) {
	oldDelays, oldBudget := webhookRetryDelays, webhookRetryBudget
	webhookRetryDelays, webhookRetryBudget = []time.Duration{time.Hour, time.Hour}, 2*time.Hour
	t.Cleanup(func() { webhookRetryDelays, webhookRetryBudget = oldDelays, oldBudget })
	called := make(chan struct{}, 1)
	calls := 0
	withWebhookTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		called <- struct{}{}
		return nil, context.DeadlineExceeded
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- postWebhookJSONContext(ctx, ChannelTeams, "https://outlook.office.com/webhook/private-token", map[string]string{"text": "test"})
	}()
	<-called
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("retry wait ignored context cancellation")
	}
	if calls != 1 {
		t.Fatalf("attempts = %d, want no retry after cancellation", calls)
	}
}

func TestWebhookRetriesAreBounded(t *testing.T) {
	oldDelays := webhookRetryDelays
	webhookRetryDelays = []time.Duration{0, 0}
	t.Cleanup(func() { webhookRetryDelays = oldDelays })
	calls := 0
	withWebhookTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, context.DeadlineExceeded
	}))
	if err := postWebhookJSON(ChannelTeams, "https://outlook.office.com/webhook/private-token", map[string]string{"text": "test"}); err == nil {
		t.Fatal("expected exhausted transient failure")
	}
	if calls != 3 {
		t.Fatalf("attempts = %d, want initial attempt plus two retries", calls)
	}
}

func TestWebhookRetryAfterWithinBudgetRetries(t *testing.T) {
	oldDelays, oldBudget := webhookRetryDelays, webhookRetryBudget
	webhookRetryDelays, webhookRetryBudget = []time.Duration{0, 0}, time.Second
	t.Cleanup(func() { webhookRetryDelays, webhookRetryBudget = oldDelays, oldBudget })
	calls := 0
	withWebhookTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"0"}}, Body: io.NopCloser(strings.NewReader("private"))}, nil
		}
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	}))
	if err := postWebhookJSON(ChannelTeams, "https://outlook.office.com/webhook/private-token", map[string]string{"text": "test"}); err != nil {
		t.Fatalf("retry after 0 did not recover: %v", err)
	}
	if calls != 2 {
		t.Fatalf("attempts = %d, want 2", calls)
	}
}

func TestFlushPendingDefersLongWebhookRetryAfter(t *testing.T) {
	oldDelays, oldBudget := webhookRetryDelays, webhookRetryBudget
	webhookRetryDelays, webhookRetryBudget = []time.Duration{0, 0}, time.Millisecond
	t.Cleanup(func() { webhookRetryDelays, webhookRetryBudget = oldDelays, oldBudget })
	calls := 0
	withWebhookTransport(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"60"}}, Body: io.NopCloser(strings.NewReader("private"))}, nil
	}))
	now := time.Now().UTC()
	brief := Brief{Slug: "pending-brief", Title: "Pending", Severity: "high"}
	store := &mockDispatchStore{
		subs:    []Subscription{{ID: "sub", Channel: ChannelTeams, WebhookURL: "https://outlook.office.com/webhook/private-token"}},
		pending: map[string]PendingDispatch{"sub": {SubscriptionID: "sub", Briefs: []Brief{brief}, FirstQueuedAt: now.Add(-time.Hour), LastQueuedAt: now.Add(-time.Hour)}},
	}
	d := &dispatcher{store: store, mailer: &mockMailer{}, logger: slog.Default()}
	_, failed := d.FlushPending(context.Background(), time.Minute, "https://example.com")
	if failed != 1 {
		t.Fatalf("failed = %d, want 1 deferred delivery", failed)
	}
	if len(store.pending["sub"].Briefs) != 1 {
		t.Fatal("failed webhook delivery did not retain its pending brief")
	}
	if retryAt := store.deferredPending["sub"]; retryAt.Before(now.Add(59 * time.Second)) {
		t.Fatalf("retry deferred until %v, want at least 59 seconds from now", retryAt)
	}
	_, _ = d.FlushPending(context.Background(), time.Minute, "https://example.com")
	if calls != 1 {
		t.Fatalf("deferred queue sent %d times before Retry-After deadline", calls)
	}
}

func TestFlushPendingAcknowledgesOnlyDeliveredSnapshot(t *testing.T) {
	brief := Brief{Slug: "delivered", Title: "Delivered", Severity: "high"}
	concurrent := Brief{Slug: "arrived-during-send", Title: "Concurrent", Severity: "medium"}
	store := &mockDispatchStore{
		subs:    []Subscription{{ID: "sub", Channel: ChannelTeams, WebhookURL: "https://outlook.office.com/webhook/private-token"}},
		pending: map[string]PendingDispatch{"sub": {SubscriptionID: "sub", Briefs: []Brief{brief}, FirstQueuedAt: time.Now().Add(-time.Hour), LastQueuedAt: time.Now().Add(-time.Hour)}},
	}
	oldClient := webhookClient
	webhookClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		pd := store.pending["sub"]
		pd.Briefs = append(pd.Briefs, concurrent)
		store.pending["sub"] = pd
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})}
	t.Cleanup(func() { webhookClient = oldClient })
	d := &dispatcher{store: store, mailer: &mockMailer{}, logger: slog.Default()}
	sent, failed := d.FlushPending(context.Background(), time.Minute, "https://example.com")
	if sent != 1 || failed != 0 {
		t.Fatalf("sent=%d failed=%d, want one successful webhook", sent, failed)
	}
	pd, ok := store.pending["sub"]
	if !ok || len(pd.Briefs) != 1 || pd.Briefs[0].Slug != concurrent.Slug {
		t.Fatalf("queue after snapshot acknowledgement = %+v, want concurrent brief retained", pd)
	}
}
