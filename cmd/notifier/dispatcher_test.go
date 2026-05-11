package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// --- mock store ---

type mockDispatchStore struct {
	subs             []Subscription
	enqueueOverflow  map[string]bool
	pending          map[string]PendingDispatch
	smtpBackoffUntil time.Time
	capturedBackoff  time.Time // set by SetSmtpBackoffUntil
}

func (m *mockDispatchStore) ForEachVerified(_ context.Context, fn func(Subscription) error) error {
	for _, s := range m.subs {
		if err := fn(s); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockDispatchStore) EnqueuePending(_ context.Context, subID string, _ []Brief) (bool, error) {
	return m.enqueueOverflow[subID], nil
}

func (m *mockDispatchStore) GetPending(_ context.Context, subID string) (PendingDispatch, error) {
	pd, ok := m.pending[subID]
	if !ok {
		return PendingDispatch{}, ErrNotFound
	}
	return pd, nil
}

func (m *mockDispatchStore) DeletePending(_ context.Context, _ string) error { return nil }

func (m *mockDispatchStore) ForEachFlushablePending(_ context.Context, _, _ time.Time, fn func(PendingDispatch) error) error {
	for _, pd := range m.pending {
		if err := fn(pd); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockDispatchStore) GetSubscription(_ context.Context, id string) (Subscription, error) {
	for _, s := range m.subs {
		if s.ID == id {
			return s, nil
		}
	}
	return Subscription{}, ErrNotFound
}

func (m *mockDispatchStore) MarkSent(_ context.Context, _ string, _ time.Time) error { return nil }

func (m *mockDispatchStore) GetSmtpBackoffUntil(_ context.Context) (time.Time, error) {
	return m.smtpBackoffUntil, nil
}

func (m *mockDispatchStore) SetSmtpBackoffUntil(_ context.Context, until time.Time) error {
	m.capturedBackoff = until
	return nil
}

// --- mock mailer ---

type mockMailer struct {
	sendCalls   int
	batchCalls  [][]SmtpMessage
	batchErrAll error // if set, fans this error to all slots in SendBatch
}

func (m *mockMailer) Send(_, _, _ string) error {
	m.sendCalls++
	return nil
}

func (m *mockMailer) SendBatch(messages []SmtpMessage) []error {
	m.batchCalls = append(m.batchCalls, append([]SmtpMessage(nil), messages...))
	errs := make([]error, len(messages))
	if m.batchErrAll != nil {
		fillAll(errs, m.batchErrAll)
	}
	return errs
}

// --- tests ---

// Email overflows during Dispatch must be sent via one SendBatch call,
// not via individual Send calls. This mirrors how FlushPending already
// works, and avoids the login-rate burst that originally caused the
// Workspace lockout.
func TestDispatch_OverflowEmailsBatchedViaSendBatch(t *testing.T) {
	briefs := []Brief{{Slug: "b1", Title: "Test Brief", Severity: "high"}}
	sub1 := Subscription{ID: "sub1", Channel: ChannelEmail, Email: "a@example.com"}
	sub2 := Subscription{ID: "sub2", Channel: ChannelEmail, Email: "b@example.com"}

	store := &mockDispatchStore{
		subs:            []Subscription{sub1, sub2},
		enqueueOverflow: map[string]bool{"sub1": true, "sub2": true},
		pending: map[string]PendingDispatch{
			"sub1": {SubscriptionID: "sub1", Briefs: briefs},
			"sub2": {SubscriptionID: "sub2", Briefs: briefs},
		},
	}
	mailer := &mockMailer{}
	d := &dispatcher{store: store, mailer: mailer, logger: slog.Default()}

	d.Dispatch(context.Background(), briefs, "https://example.com")

	if mailer.sendCalls != 0 {
		t.Errorf("Send called %d times; want 0 — email overflows must use SendBatch", mailer.sendCalls)
	}
	if len(mailer.batchCalls) != 1 {
		t.Fatalf("SendBatch called %d times; want 1", len(mailer.batchCalls))
	}
	if len(mailer.batchCalls[0]) != 2 {
		t.Errorf("SendBatch received %d messages; want 2", len(mailer.batchCalls[0]))
	}
}

// When a SMTP backoff is active, FlushPending must not attempt any
// SMTP connection. Pending queues stay intact so the next sweep retries
// once the backoff expires.
func TestFlushPending_SkipsSmtpDuringBackoff(t *testing.T) {
	sub := Subscription{ID: "sub1", Channel: ChannelEmail, Email: "a@example.com"}
	briefs := []Brief{{Slug: "b1", Title: "Test Brief", Severity: "high"}}
	ago := time.Now().Add(-10 * time.Minute)

	store := &mockDispatchStore{
		subs:             []Subscription{sub},
		smtpBackoffUntil: time.Now().Add(1 * time.Hour),
		pending: map[string]PendingDispatch{
			"sub1": {SubscriptionID: "sub1", Briefs: briefs, FirstQueuedAt: ago, LastQueuedAt: ago},
		},
	}
	mailer := &mockMailer{}
	d := &dispatcher{store: store, mailer: mailer, logger: slog.Default()}

	_, failed := d.FlushPending(context.Background(), 5*time.Minute, "https://example.com")

	if len(mailer.batchCalls) != 0 {
		t.Errorf("SendBatch called %d times during backoff; want 0", len(mailer.batchCalls))
	}
	if failed != 1 {
		t.Errorf("failed count = %d; want 1", failed)
	}
}

// When SendBatch returns a connection-level error (e.g. STARTTLS EOF)
// for every recipient, FlushPending must persist a backoff timestamp so
// the next sweeps skip SMTP instead of hammering the locked-out relay.
func TestFlushPending_SetsBackoffAfterConnectionFailure(t *testing.T) {
	sub := Subscription{ID: "sub1", Channel: ChannelEmail, Email: "a@example.com"}
	briefs := []Brief{{Slug: "b1", Title: "Test Brief", Severity: "high"}}
	ago := time.Now().Add(-10 * time.Minute)

	store := &mockDispatchStore{
		subs: []Subscription{sub},
		pending: map[string]PendingDispatch{
			"sub1": {SubscriptionID: "sub1", Briefs: briefs, FirstQueuedAt: ago, LastQueuedAt: ago},
		},
	}
	mailer := &mockMailer{batchErrAll: &smtpConnError{err: errors.New("EOF")}}
	d := &dispatcher{store: store, mailer: mailer, logger: slog.Default()}

	d.FlushPending(context.Background(), 5*time.Minute, "https://example.com")

	if store.capturedBackoff.IsZero() {
		t.Fatal("SetSmtpBackoffUntil not called after all-connection-error batch")
	}
	if !store.capturedBackoff.After(time.Now()) {
		t.Errorf("backoff set to %v; want a future time", store.capturedBackoff)
	}
}
