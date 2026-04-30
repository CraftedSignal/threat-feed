package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

type server struct {
	cfg        *config
	store      *firestoreStore
	mailer     mailer
	dispatcher *dispatcher
	logger     *slog.Logger
}

const (
	// /subscribe accepts a small JSON form; cap well above realistic max.
	maxBodyBytes = 64 * 1024
	// /dispatch can receive a batch of brief metadata; cap higher.
	maxDispatchBodyBytes = 1 * 1024 * 1024
)

func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *server) handleFavicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(faviconSVG)
}

// POST /subscribe — JSON body: {channel, email|webhook_url, filter}.
// On success, stores a pending verification and emails (or — for
// webhook channels — directly issues a confirmation token in the
// response body, since webhooks don't have an inbox to verify into).
func (s *server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req subscribeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	sub, err := req.toSubscription()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sub.ID = newToken()
	sub.UnsubscribeToken = newToken()
	sub.CreatedAt = time.Now().UTC()

	verifyToken := newToken()
	ctx := r.Context()

	switch sub.Channel {
	case ChannelEmail:
		// Two-step: pending row + email with magic link.
		if err := s.store.CreatePending(ctx, verifyToken, sub); err != nil {
			s.logger.Error("create pending failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		body := s.verifyEmailBody(verifyToken)
		if err := s.mailer.Send(sub.Email, "Confirm your CraftedSignal feed subscription", body); err != nil {
			s.logger.Error("verification mail failed", "err", err)
			http.Error(w, "email send failed", http.StatusBadGateway)
			return
		}
	case ChannelSlack, ChannelTeams:
		// Webhook channels can't receive an email-style confirmation.
		// The webhook URL itself is the secret — possessing it means
		// you can post into the destination, which we treat as
		// implicit consent. Skip pending; verify immediately.
		sub.VerifiedAt = time.Now().UTC()
		if err := s.store.SaveSubscription(ctx, sub); err != nil {
			s.logger.Error("save sub failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "unknown channel", http.StatusBadRequest)
		return
	}

	respondJSON(w, http.StatusAccepted, map[string]any{
		"status":  "ok",
		"channel": sub.Channel,
	})
}

// GET /verify?token=… — confirm an emailed subscription.
func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.redirectSiteError(w, r)
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		s.redirectSiteError(w, r)
		return
	}

	ctx := r.Context()
	sub, err := s.store.ConsumePending(ctx, token)
	if err != nil {
		if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrExpired) {
			s.logger.Error("consume pending failed", "err", err)
		}
		s.redirectSiteError(w, r)
		return
	}

	sub.VerifiedAt = time.Now().UTC()
	// The pending doc serialized the Subscription with `firestore:"-"`
	// on ID, so the value set in handleSubscribe was dropped on the
	// way through Firestore. ID is purely the doc key in the verified
	// collection — re-mint one here.
	sub.ID = newToken()
	// Re-subscribing should replace, not duplicate. Drop any prior
	// verified row for this address+channel before writing the new one
	// — if the cleanup fails we still try the write so a Firestore
	// hiccup doesn't block the user; worst case they end up with a
	// duplicate, which the dispatcher already tolerates.
	if sub.Email != "" {
		if n, err := s.store.DeleteVerifiedByEmail(ctx, sub.Email, sub.Channel); err != nil {
			s.logger.Warn("dedup verified subs failed", "err", err)
		} else if n > 0 {
			s.logger.Info("replaced existing subscription on re-verify", "to_hash", hashEmail(sub.Email), "removed", n)
		}
	}
	if err := s.store.SaveSubscription(ctx, sub); err != nil {
		s.logger.Error("save verified sub failed", "err", err)
		s.redirectSiteError(w, r)
		return
	}

	// 303 to a confirmation page on the static site.
	dest, _ := url.Parse(s.cfg.SiteOrigin)
	dest.Path = "/subscribe/confirmed/"
	http.Redirect(w, r, dest.String(), http.StatusSeeOther)
}

// redirectSiteError sends the user to the friendly /subscribe/error/
// page on the static site instead of dumping a plaintext http.Error.
// Server-side reasons stay in the logs; users get the same "try again"
// CTA regardless of which failure mode they hit.
func (s *server) redirectSiteError(w http.ResponseWriter, r *http.Request) {
	dest, _ := url.Parse(s.cfg.SiteOrigin)
	dest.Path = "/subscribe/error/"
	http.Redirect(w, r, dest.String(), http.StatusSeeOther)
}

// GET /unsubscribe?token=…
func (s *server) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.redirectSiteError(w, r)
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		s.redirectSiteError(w, r)
		return
	}
	if err := s.store.DeleteByUnsubscribeToken(r.Context(), token); err != nil {
		if !errors.Is(err, ErrNotFound) {
			s.logger.Error("delete sub failed", "err", err)
		}
		s.redirectSiteError(w, r)
		return
	}
	dest, _ := url.Parse(s.cfg.SiteOrigin)
	dest.Path = "/subscribe/unsubscribed/"
	http.Redirect(w, r, dest.String(), http.StatusSeeOther)
}

// POST /dispatch — bearer-authed; body is { briefs: [...] }. Called by
// the threat-feed Site Deploy workflow on every successful build.
func (s *server) handleDispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkDispatchAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxDispatchBodyBytes)
	var req dispatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if len(req.Briefs) == 0 {
		respondJSON(w, http.StatusOK, map[string]any{"sent": 0, "failed": 0})
		return
	}

	// Detach from request ctx so a slow client can't cancel mid-dispatch.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	queued, overflowFlushed := s.dispatcher.Dispatch(ctx, req.Briefs, s.cfg.ServiceURL)
	respondJSON(w, http.StatusOK, map[string]any{
		"queued":           queued,
		"overflow_flushed": overflowFlushed,
		"briefs":           len(req.Briefs),
	})
}

// POST /flush-pending — bearer-authed; called periodically by Cloud
// Scheduler. Drains every queue with first_queued_at older than the
// debounce window, batching all matched briefs per subscriber into
// one delivery. The debounce window is fixed at 5 min server-side
// to keep the public surface minimal; tune via flushDebounce.
func (s *server) handleFlushPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkDispatchAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	const flushDebounce = 5 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sent, failed := s.dispatcher.FlushPending(ctx, flushDebounce, s.cfg.ServiceURL)
	respondJSON(w, http.StatusOK, map[string]any{
		"sent":     sent,
		"failed":   failed,
		"debounce": flushDebounce.String(),
	})
}

func (s *server) checkDispatchAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	got := []byte(auth[len(prefix):])
	want := []byte(s.cfg.DispatchToken)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func (s *server) verifyEmailBody(token string) string {
	base := s.cfg.ServiceURL
	if base == "" {
		// No SERVICE_URL set yet — degrade gracefully, ship the token
		// inline so the user can construct the link manually if needed.
		return fmt.Sprintf(`Your CraftedSignal Threat Feed subscription is awaiting confirmation.

Verification token: %s

(SERVICE_URL not yet configured; please contact the operator.)
`, token)
	}
	verifyURL := fmt.Sprintf("%s/verify?token=%s", base, token)
	return fmt.Sprintf(`Confirm your CraftedSignal Threat Feed subscription:

%s

This link expires in 24 hours. If you didn't request this, ignore the email.
`, verifyURL)
}

// ---------------------------------------------------------------------------
// Request shapes

type subscribeRequest struct {
	Channel    string `json:"channel"`
	Email      string `json:"email,omitempty"`
	WebhookURL string `json:"webhook_url,omitempty"`
	Filter     Filter `json:"filter"`
}

func (r subscribeRequest) toSubscription() (Subscription, error) {
	ch := Channel(strings.ToLower(strings.TrimSpace(r.Channel)))
	sub := Subscription{
		Channel: ch,
		Filter:  r.Filter,
	}
	switch ch {
	case ChannelEmail:
		addr, err := mail.ParseAddress(r.Email)
		if err != nil {
			return sub, fmt.Errorf("invalid email")
		}
		sub.Email = strings.ToLower(addr.Address)
	case ChannelSlack:
		if !strings.HasPrefix(r.WebhookURL, "https://hooks.slack.com/") {
			return sub, fmt.Errorf("invalid Slack webhook URL")
		}
		sub.WebhookURL = r.WebhookURL
	case ChannelTeams:
		if !strings.Contains(r.WebhookURL, "office.com/webhook") &&
			!strings.Contains(r.WebhookURL, ".webhook.office.com") &&
			!strings.Contains(r.WebhookURL, ".logic.azure.com") {
			return sub, fmt.Errorf("invalid Teams webhook URL")
		}
		sub.WebhookURL = r.WebhookURL
	default:
		return sub, fmt.Errorf("channel must be one of: email, slack, teams")
	}
	return sub, nil
}

type dispatchRequest struct {
	Briefs []Brief `json:"briefs"`
}

// ---------------------------------------------------------------------------
// Helpers

func newToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand only fails in catastrophic OS conditions
	}
	return hex.EncodeToString(b[:])
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// CORS + access log middleware

func withCORSAndLog(next http.Handler, origin string, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HSTS — every response served over HTTPS by the LB; tell
		// browsers to never downgrade.
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")

		// CORS for /subscribe — only the configured origin.
		w.Header().Set("Vary", "Origin")
		if r.Header.Get("Origin") == origin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Recaptcha-Token")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		start := time.Now()
		ww := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(ww, r)
		logger.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
