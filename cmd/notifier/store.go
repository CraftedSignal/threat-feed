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
	collSubscriptions = "subscriptions"
	collPending       = "pending_verifications"

	pendingTTL = 24 * time.Hour
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
