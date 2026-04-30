package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	collSubscriptions   = "subscriptions"
	collPending         = "pending_verifications"
	collPendingDispatch = "pending_dispatch"

	pendingTTL = 24 * time.Hour

	// pendingDispatchCap limits how many briefs a single subscriber's
	// queue can hold before the next /dispatch arrival force-flushes
	// the queue. Keeps the doc comfortably under Firestore's 1 MB
	// limit even with verbose briefs.
	pendingDispatchCap = 50
)

type firestoreStore struct {
	c *firestore.Client
}

func newFirestoreStore(ctx context.Context, projectID string) (*firestoreStore, error) {
	c, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("firestore: %w", err)
	}
	return &firestoreStore{c: c}, nil
}

func (s *firestoreStore) Close() error { return s.c.Close() }

// CreatePending stores a pre-verification subscription under the given
// token. Replaces any existing record at the same token (allows resending
// verification mail by re-submitting the form).
func (s *firestoreStore) CreatePending(ctx context.Context, token string, sub Subscription) error {
	pv := PendingVerification{
		Subscription: sub,
		ExpiresAt:    time.Now().Add(pendingTTL),
	}
	_, err := s.c.Collection(collPending).Doc(token).Set(ctx, pv)
	return err
}

// ConsumePending fetches the pending record by token and deletes it
// atomically. Returns ErrNotFound when the token isn't valid.
func (s *firestoreStore) ConsumePending(ctx context.Context, token string) (Subscription, error) {
	var sub Subscription
	err := s.c.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		ref := s.c.Collection(collPending).Doc(token)
		snap, err := tx.Get(ref)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				return ErrNotFound
			}
			return err
		}
		var pv PendingVerification
		if err := snap.DataTo(&pv); err != nil {
			return err
		}
		if time.Now().After(pv.ExpiresAt) {
			_ = tx.Delete(ref)
			return ErrExpired
		}
		sub = pv.Subscription
		return tx.Delete(ref)
	})
	return sub, err
}

// SaveSubscription persists a verified subscription, replacing any row
// with the same ID.
func (s *firestoreStore) SaveSubscription(ctx context.Context, sub Subscription) error {
	_, err := s.c.Collection(collSubscriptions).Doc(sub.ID).Set(ctx, sub)
	return err
}

// DeleteVerifiedByEmail removes every verified subscription with the
// given (email, channel) pair. Used at verify-time to make
// re-subscribing replace any existing row instead of producing
// duplicates that would each receive every brief. No-op when nothing
// matches.
func (s *firestoreStore) DeleteVerifiedByEmail(ctx context.Context, email string, channel Channel) (int, error) {
	if email == "" {
		return 0, nil
	}
	q := s.c.Collection(collSubscriptions).
		Where("email", "==", email).
		Where("channel", "==", string(channel))
	iter := q.Documents(ctx)
	defer iter.Stop()
	deleted := 0
	for {
		snap, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return deleted, nil
		}
		if err != nil {
			return deleted, err
		}
		if _, err := snap.Ref.Delete(ctx); err != nil {
			return deleted, err
		}
		deleted++
	}
}

// DeleteByUnsubscribeToken deletes the subscription that matches the
// given token. Returns ErrNotFound if no match.
func (s *firestoreStore) DeleteByUnsubscribeToken(ctx context.Context, token string) error {
	q := s.c.Collection(collSubscriptions).Where("unsubscribe_token", "==", token).Limit(1)
	iter := q.Documents(ctx)
	defer iter.Stop()
	snap, err := iter.Next()
	if errors.Is(err, iterator.Done) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = snap.Ref.Delete(ctx)
	return err
}

// ForEachVerified streams every verified subscription. Cheap at our
// scale — one read per sub per dispatch. Add cursor-based pagination
// if subscription count grows past ~10k.
func (s *firestoreStore) ForEachVerified(ctx context.Context, fn func(Subscription) error) error {
	iter := s.c.Collection(collSubscriptions).
		Where("verified_at", ">", time.Time{}).
		Documents(ctx)
	defer iter.Stop()
	for {
		snap, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return nil
		}
		if err != nil {
			return err
		}
		var sub Subscription
		if err := snap.DataTo(&sub); err != nil {
			return err
		}
		sub.ID = snap.Ref.ID
		if err := fn(sub); err != nil {
			return err
		}
	}
}

// MarkSent updates last_sent on a subscription. Best-effort — we don't
// fail the dispatch if this write errors.
func (s *firestoreStore) MarkSent(ctx context.Context, id string, t time.Time) error {
	_, err := s.c.Collection(collSubscriptions).Doc(id).Update(ctx, []firestore.Update{
		{Path: "last_sent", Value: t},
	})
	return err
}

var (
	ErrNotFound = errors.New("subscription not found")
	ErrExpired  = errors.New("verification token expired")
)

// GetSubscription fetches a single verified subscription by ID. Used at
// flush-time to pair a queued PendingDispatch with the subscriber's
// current channel / email / unsubscribe token. Returns ErrNotFound if
// the subscription has been removed since the brief was queued.
func (s *firestoreStore) GetSubscription(ctx context.Context, id string) (Subscription, error) {
	var sub Subscription
	snap, err := s.c.Collection(collSubscriptions).Doc(id).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return sub, ErrNotFound
		}
		return sub, err
	}
	if err := snap.DataTo(&sub); err != nil {
		return sub, err
	}
	sub.ID = snap.Ref.ID
	return sub, nil
}

// EnqueuePending appends matched briefs to a subscription's pending
// dispatch queue, creating the doc on first use. Idempotent on slug
// (briefs already in the queue are not re-added). Returns true when
// the post-append queue depth has reached pendingDispatchCap, so the
// caller can trigger an immediate flush for that subscription instead
// of waiting for the next periodic sweep.
func (s *firestoreStore) EnqueuePending(ctx context.Context, subID string, briefs []Brief) (overflow bool, err error) {
	if subID == "" || len(briefs) == 0 {
		return false, nil
	}
	ref := s.c.Collection(collPendingDispatch).Doc(subID)
	now := time.Now().UTC()

	err = s.c.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		var pd PendingDispatch
		snap, err := tx.Get(ref)
		if err != nil && status.Code(err) != codes.NotFound {
			return err
		}
		if err == nil {
			if perr := snap.DataTo(&pd); perr != nil {
				return perr
			}
		}
		seen := make(map[string]struct{}, len(pd.Briefs))
		for _, b := range pd.Briefs {
			seen[b.Slug] = struct{}{}
		}
		for _, b := range briefs {
			if _, dup := seen[b.Slug]; dup {
				continue
			}
			seen[b.Slug] = struct{}{}
			pd.Briefs = append(pd.Briefs, b)
		}
		if pd.FirstQueuedAt.IsZero() {
			pd.FirstQueuedAt = now
		}
		pd.LastQueuedAt = now
		if len(pd.Briefs) >= pendingDispatchCap {
			overflow = true
		}
		return tx.Set(ref, pd)
	})
	return overflow, err
}

// ForEachFlushablePending iterates pending_dispatch docs whose
// first_queued_at is older than cutoff, decoding each into a
// PendingDispatch. fn is called sequentially; the iteration unsubscribes
// on the first error.
func (s *firestoreStore) ForEachFlushablePending(ctx context.Context, cutoff time.Time, fn func(PendingDispatch) error) error {
	iter := s.c.Collection(collPendingDispatch).
		Where("first_queued_at", "<=", cutoff).
		Documents(ctx)
	defer iter.Stop()
	for {
		snap, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return nil
		}
		if err != nil {
			return err
		}
		var pd PendingDispatch
		if err := snap.DataTo(&pd); err != nil {
			return err
		}
		pd.SubscriptionID = snap.Ref.ID
		if err := fn(pd); err != nil {
			return err
		}
	}
}

// DeletePending removes the queue doc for a subscription. Called after
// a successful batched delivery. Best-effort: a delete failure leaves
// the queue in place and the next flush retries.
func (s *firestoreStore) DeletePending(ctx context.Context, subID string) error {
	_, err := s.c.Collection(collPendingDispatch).Doc(subID).Delete(ctx)
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}
