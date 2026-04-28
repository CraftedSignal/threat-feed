package main

import "time"

// Channel — where notifications go.
type Channel string

const (
	ChannelEmail Channel = "email"
	ChannelSlack Channel = "slack"
	ChannelTeams Channel = "teams"
)

// Filter narrows which briefs trigger a notification. AND across fields,
// OR within slices. Empty slice on a field means "any value" for that
// field (i.e. no constraint).
type Filter struct {
	Types      []string `firestore:"types,omitempty"      json:"types,omitempty"`
	Severities []string `firestore:"severities,omitempty" json:"severities,omitempty"`
	Actors     []string `firestore:"actors,omitempty"     json:"actors,omitempty"`
	Vendors    []string `firestore:"vendors,omitempty"    json:"vendors,omitempty"`
	Products   []string `firestore:"products,omitempty"   json:"products,omitempty"`
	Tags       []string `firestore:"tags,omitempty"       json:"tags,omitempty"`
	Exploited  bool     `firestore:"exploited,omitempty"  json:"exploited,omitempty"`
}

// Subscription — one delivery target with one filter.
type Subscription struct {
	ID         string    `firestore:"-"                    json:"id"`
	Channel    Channel   `firestore:"channel"              json:"channel"`
	Email      string    `firestore:"email,omitempty"      json:"email,omitempty"`
	WebhookURL string    `firestore:"webhook_url,omitempty" json:"webhook_url,omitempty"`
	Filter     Filter    `firestore:"filter"               json:"filter"`
	VerifiedAt time.Time `firestore:"verified_at,omitempty" json:"verified_at,omitempty"`

	UnsubscribeToken string `firestore:"unsubscribe_token" json:"-"`

	CreatedAt time.Time `firestore:"created_at" json:"created_at"`
	LastSent  time.Time `firestore:"last_sent,omitempty" json:"last_sent,omitempty"`
}

// PendingVerification holds a not-yet-confirmed subscription. Stored in a
// separate collection with a TTL field so Firestore reaps stale ones.
type PendingVerification struct {
	Token        string       `firestore:"-"`
	Subscription Subscription `firestore:"subscription"`
	ExpiresAt    time.Time    `firestore:"expires_at"`
}

// Brief — minimal subset that the dispatcher needs from each new public
// brief. Posted by the threat-feed Site Deploy workflow.
type Brief struct {
	Slug        string   `json:"slug"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	URL         string   `json:"url"`
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Actors      []string `json:"actors,omitempty"`
	Vendors     []string `json:"vendors,omitempty"`
	Products    []string `json:"products,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Exploited   bool     `json:"exploited,omitempty"`
}
