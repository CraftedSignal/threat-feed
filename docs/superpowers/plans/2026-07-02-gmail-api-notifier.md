# Gmail API Notifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Send the notifier's emails via the Gmail API over HTTPS (keyless domain-wide delegation) instead of SMTP, which Gmail blocks from Cloud Run egress.

**Architecture:** Add a `gmailMailer` that satisfies the existing `mailer` interface, so `handlers.go`/`dispatcher.go` are untouched. It reuses the current MIME builder (extracted to a shared `buildRFC822`), base64url-encodes the message, and calls `gmail.Users.Messages.Send`. Auth is keyless: the Cloud Run runtime SA self-impersonates with a DWD `Subject` via the IAM Credentials API. `main.go` selects the backend by env.

**Tech Stack:** Go, `google.golang.org/api/gmail/v1`, `google.golang.org/api/impersonate`, `google.golang.org/api/option`, `cloud.google.com/go/compute/metadata` (all already transitively in `go.mod`); Terraform (`google_cloud_run_v2_service`, `google_service_account_iam_member`).

## Global Constraints

- Module path root: `/Users/niels/Source/craftedsignal/threat-feed`; notifier package is `package main` in `cmd/notifier/`.
- Run tests from the threat-feed root: `go test ./cmd/notifier/...`.
- Sender identity: DWD `Subject` = `nhofmans@craftedsignal.io` (real user); `From:` header = `feed-noreply@craftedsignal.io` (alias). `userId` for the Gmail send is the literal `"me"` (resolves to the impersonated subject).
- Gmail scope: `https://www.googleapis.com/auth/gmail.send`.
- Do NOT change the `mailer` interface, `SmtpMessage`, `handlers.go`, or `dispatcher.go`.
- Preserve the dispatcher's backoff contract: a total send failure must surface as `*smtpConnError` in every result slot.
- Prereq gating final verification (Task 6): user authorizes SA client ID `112753602460856002671` for the gmail.send scope in Google Admin → Domain-wide delegation.

---

### Task 1: Extract shared RFC822 builder

Refactor the existing `(*smtpMailer).formatMessage` into a package-level `buildRFC822(from string, msg SmtpMessage) string` so both mailers produce identical MIME. Pure refactor — no behavior change.

**Files:**
- Modify: `cmd/notifier/mailer.go` (replace `formatMessage` method; update `sendOne` call site)
- Test: `cmd/notifier/mailer_format_test.go` (create)

**Interfaces:**
- Produces: `buildRFC822(from string, msg SmtpMessage) string` — full RFC822 message; plain-text when `HTMLBody==""`, else `multipart/alternative`.

- [ ] **Step 1: Write the failing test**

```go
// cmd/notifier/mailer_format_test.go
package main

import "testing"

func TestBuildRFC822_PlainAndMultipart(t *testing.T) {
	plain := buildRFC822("feed-noreply@craftedsignal.io", SmtpMessage{To: "a@example.com", Subject: "Hi", TextBody: "hello"})
	for _, want := range []string{"From: feed-noreply@craftedsignal.io", "To: a@example.com", "Subject: Hi", "text/plain; charset=utf-8", "hello"} {
		if !contains(plain, want) {
			t.Fatalf("plain message missing %q\n---\n%s", want, plain)
		}
	}
	multi := buildRFC822("feed-noreply@craftedsignal.io", SmtpMessage{To: "b@example.com", Subject: "Hey", TextBody: "t", HTMLBody: "<b>h</b>"})
	for _, want := range []string{"multipart/alternative; boundary=", "text/plain; charset=utf-8", "text/html; charset=utf-8"} {
		if !contains(multi, want) {
			t.Fatalf("multipart message missing %q\n---\n%s", want, multi)
		}
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/notifier/ -run TestBuildRFC822 -v`
Expected: FAIL — `undefined: buildRFC822`.

- [ ] **Step 3: Refactor `formatMessage` into `buildRFC822`**

In `cmd/notifier/mailer.go`, change the method signature and body header to take `from` explicitly, and update the single caller. Replace:

```go
func (m *smtpMailer) formatMessage(msg SmtpMessage) string {
	var body strings.Builder
	writeHeader(&body, "From", sanitizeHeaderValue(m.cfg.From))
```

with:

```go
func buildRFC822(from string, msg SmtpMessage) string {
	var body strings.Builder
	writeHeader(&body, "From", sanitizeHeaderValue(from))
```

(the rest of the function body is unchanged — it already uses `msg.*`). Then in `sendOne`, change:

```go
	if _, err := w.Write([]byte(m.formatMessage(msg))); err != nil {
```

to:

```go
	if _, err := w.Write([]byte(buildRFC822(m.cfg.From, msg))); err != nil {
```

- [ ] **Step 4: Run tests to verify pass**

Run: `go test ./cmd/notifier/ -run TestBuildRFC822 -v && go build ./cmd/notifier/`
Expected: PASS and clean build.

- [ ] **Step 5: Commit**

```bash
git -C /Users/niels/Source/craftedsignal/threat-feed add cmd/notifier/mailer.go cmd/notifier/mailer_format_test.go
git -C /Users/niels/Source/craftedsignal/threat-feed commit -m "refactor(notifier): extract buildRFC822 shared MIME builder"
```

---

### Task 2: gmailMailer core (testable, no live API)

Implement the `mailer` interface over an injected `rawSender` so the build/encode/error logic is unit-tested without touching Google.

**Files:**
- Create: `cmd/notifier/gmail_mailer.go`
- Test: `cmd/notifier/gmail_mailer_test.go`

**Interfaces:**
- Consumes: `buildRFC822` (Task 1), `SmtpMessage`, `smtpConnError`, `hashEmail` (existing in `mailer.go`).
- Produces: `rawSender` interface (`Send(userID, raw string) error`); `gmailMailer` struct with fields `from string`, `userID string`, `sender rawSender`, `logger *slog.Logger`; constructor `newGmailMailerWith(from string, sender rawSender, logger *slog.Logger) *gmailMailer`; `encodeRaw(rfc822 string) string`.

- [ ] **Step 1: Write the failing test**

```go
// cmd/notifier/gmail_mailer_test.go
package main

import (
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"testing"
)

type fakeSender struct {
	calls []string // captured userIDs
	raws  []string
	err   error
}

func (f *fakeSender) Send(userID, raw string) error {
	f.calls = append(f.calls, userID)
	f.raws = append(f.raws, raw)
	return f.err
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestGmailMailer_SendEncodesAndAddressesMe(t *testing.T) {
	f := &fakeSender{}
	m := newGmailMailerWith("feed-noreply@craftedsignal.io", f, testLogger())
	if err := m.Send("x@example.com", "Subj", "body", ""); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.calls) != 1 || f.calls[0] != "me" {
		t.Fatalf("userID = %v, want [me]", f.calls)
	}
	decoded, err := base64.URLEncoding.DecodeString(f.raws[0])
	if err != nil {
		t.Fatalf("raw not base64url: %v", err)
	}
	if !contains(string(decoded), "From: feed-noreply@craftedsignal.io") || !contains(string(decoded), "To: x@example.com") {
		t.Fatalf("decoded message missing headers:\n%s", decoded)
	}
}

func TestGmailMailer_SendBatchWrapsTotalFailureAsConnError(t *testing.T) {
	f := &fakeSender{err: errors.New("401 unauthorized_client")}
	m := newGmailMailerWith("feed-noreply@craftedsignal.io", f, testLogger())
	errs := m.SendBatch([]SmtpMessage{{To: "a@x.com"}, {To: "b@x.com"}})
	if len(errs) != 2 {
		t.Fatalf("len(errs) = %d, want 2", len(errs))
	}
	for i, e := range errs {
		var ce *smtpConnError
		if !errors.As(e, &ce) {
			t.Fatalf("errs[%d] = %v, want *smtpConnError", i, e)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/notifier/ -run TestGmailMailer -v`
Expected: FAIL — `undefined: newGmailMailerWith`.

- [ ] **Step 3: Implement gmailMailer core**

```go
// cmd/notifier/gmail_mailer.go
package main

import (
	"encoding/base64"
	"fmt"
	"log/slog"
)

// rawSender abstracts the Gmail "send a raw RFC822 message" call so
// gmailMailer's build/encode/error logic is unit-testable without live API.
type rawSender interface {
	Send(userID, raw string) error
}

// gmailMailer implements mailer over the Gmail API. It builds the same
// RFC822 message the SMTP path did and submits it as a base64url Raw body.
type gmailMailer struct {
	from   string // From: header (the feed-noreply@ alias)
	userID string // Gmail userId; "me" = the impersonated DWD subject
	sender rawSender
	logger *slog.Logger
}

func newGmailMailerWith(from string, sender rawSender, logger *slog.Logger) *gmailMailer {
	return &gmailMailer{from: from, userID: "me", sender: sender, logger: logger}
}

func encodeRaw(rfc822 string) string {
	return base64.URLEncoding.EncodeToString([]byte(rfc822))
}

func (m *gmailMailer) Send(to, subject, textBody, htmlBody string) error {
	raw := encodeRaw(buildRFC822(m.from, SmtpMessage{To: to, Subject: subject, TextBody: textBody, HTMLBody: htmlBody}))
	if err := m.sender.Send(m.userID, raw); err != nil {
		m.logger.Error("gmail send failed", "to_hash", hashEmail(to), "err", err)
		return fmt.Errorf("gmail send: %w", err)
	}
	return nil
}

// SendBatch sends each message with its own API call. Every failure is
// wrapped as *smtpConnError so the dispatcher's existing "all failed ->
// back off" logic still triggers when auth/quota knocks out the whole batch.
func (m *gmailMailer) SendBatch(messages []SmtpMessage) []error {
	out := make([]error, len(messages))
	for i, msg := range messages {
		raw := encodeRaw(buildRFC822(m.from, msg))
		if err := m.sender.Send(m.userID, raw); err != nil {
			m.logger.Error("gmail send failed", "to_hash", hashEmail(msg.To), "err", err)
			out[i] = &smtpConnError{err: fmt.Errorf("gmail send: %w", err)}
		}
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify pass**

Run: `go test ./cmd/notifier/ -run TestGmailMailer -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git -C /Users/niels/Source/craftedsignal/threat-feed add cmd/notifier/gmail_mailer.go cmd/notifier/gmail_mailer_test.go
git -C /Users/niels/Source/craftedsignal/threat-feed commit -m "feat(notifier): gmailMailer implementing mailer over injected rawSender"
```

---

### Task 3: Production Gmail sender + keyless DWD constructor

Wire the real Gmail service behind `rawSender` and construct it with keyless domain-wide delegation. Not unit-tested (needs GCP creds + DWD); verified by build/vet here and end-to-end in Task 6.

**Files:**
- Modify: `cmd/notifier/gmail_mailer.go` (add `gmailAPISender` + `newGmailMailer`)

**Interfaces:**
- Consumes: `config` with `SMTP.From` (From address) and `Gmail.Subject` (Task 4 adds `Gmail`).
- Produces: `newGmailMailer(ctx context.Context, cfg *config, logger *slog.Logger) (*gmailMailer, error)`.

- [ ] **Step 1: Add imports and the API-backed sender + constructor**

Append to `cmd/notifier/gmail_mailer.go` (and extend the import block):

```go
import (
	"context"

	"cloud.google.com/go/compute/metadata"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

type gmailAPISender struct{ svc *gmail.Service }

func (s *gmailAPISender) Send(userID, raw string) error {
	_, err := s.svc.Users.Messages.Send(userID, &gmail.Message{Raw: raw}).Do()
	return err
}

// newGmailMailer builds a gmailMailer using keyless domain-wide delegation:
// the Cloud Run runtime SA (discovered from the metadata server) impersonates
// itself with a DWD Subject, signing via the IAM Credentials API — no key.
func newGmailMailer(ctx context.Context, cfg *config, logger *slog.Logger) (*gmailMailer, error) {
	saEmail, err := metadata.EmailWithContext(ctx, "default")
	if err != nil {
		return nil, fmt.Errorf("discover runtime service account: %w", err)
	}
	ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		TargetPrincipal: saEmail,
		Scopes:          []string{gmail.GmailSendScope},
		Subject:         cfg.Gmail.Subject,
	})
	if err != nil {
		return nil, fmt.Errorf("build delegated token source: %w", err)
	}
	svc, err := gmail.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		return nil, fmt.Errorf("gmail service: %w", err)
	}
	logger.Info("gmail mailer ready", "delegate_sa", saEmail, "subject", cfg.Gmail.Subject, "from", cfg.SMTP.From)
	return newGmailMailerWith(cfg.SMTP.From, &gmailAPISender{svc: svc}, logger), nil
}
```

- [ ] **Step 2: Resolve dependencies**

Run: `cd /Users/niels/Source/craftedsignal/threat-feed && go get google.golang.org/api/gmail/v1@v0.283.0 && go mod tidy`
Expected: `go.mod` gains `google.golang.org/api/gmail/v1`, `.../impersonate`, and promotes `compute/metadata` as needed; no version downgrades of `google.golang.org/api`.

- [ ] **Step 3: Build + vet (compile check for the untested constructor)**

Run: `go build ./cmd/notifier/ && go vet ./cmd/notifier/`
Expected: no output (success). If `metadata.EmailWithContext` is unavailable in the pinned version, use `metadata.Email("default")` instead.

- [ ] **Step 4: Commit**

```bash
git -C /Users/niels/Source/craftedsignal/threat-feed add cmd/notifier/gmail_mailer.go go.mod go.sum
git -C /Users/niels/Source/craftedsignal/threat-feed commit -m "feat(notifier): keyless DWD Gmail sender constructor"
```

---

### Task 4: Config + main.go backend selection

Add `MAILER_BACKEND` (default `gmail`) and `GMAIL_SUBJECT`; make SMTP host/user/pass required only for the smtp backend; keep `SMTP_FROM` required for both (it is the From header).

**Files:**
- Modify: `cmd/notifier/config.go`
- Modify: `cmd/notifier/main.go`
- Test: `cmd/notifier/config_test.go` (create)

**Interfaces:**
- Consumes: existing `mustEnv`/`getEnv`, `smtpConfig`.
- Produces: `config.MailerBackend string`; `config.Gmail gmailConfig{ Subject string }`.

- [ ] **Step 1: Write the failing test**

```go
// cmd/notifier/config_test.go
package main

import "testing"

func TestLoadConfig_GmailBackendSkipsSMTPCreds(t *testing.T) {
	base := map[string]string{
		"PROJECT_ID": "p", "SITE_ORIGIN": "https://s", "DISPATCH_TOKEN": "t",
		"SMTP_FROM": "feed-noreply@craftedsignal.io", "MAILER_BACKEND": "gmail",
		"GMAIL_SUBJECT": "nhofmans@craftedsignal.io",
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig (gmail, no SMTP creds set): %v", err)
	}
	if cfg.MailerBackend != "gmail" || cfg.Gmail.Subject != "nhofmans@craftedsignal.io" {
		t.Fatalf("unexpected cfg: backend=%q subject=%q", cfg.MailerBackend, cfg.Gmail.Subject)
	}
	if cfg.SMTP.From != "feed-noreply@craftedsignal.io" {
		t.Fatalf("SMTP.From = %q", cfg.SMTP.From)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/notifier/ -run TestLoadConfig -v`
Expected: FAIL — either `cfg.MailerBackend` undefined (compile error) or a panic from `mustEnv("SMTP_HOST")`.

- [ ] **Step 3: Implement config changes**

In `cmd/notifier/config.go`, add to the `config` struct: `MailerBackend string` and `Gmail gmailConfig`; add `type gmailConfig struct{ Subject string }`. Replace the `loadConfig` SMTP section so SMTP creds are conditional:

```go
func loadConfig() (*config, error) {
	cfg := &config{
		ProjectID:     mustEnv("PROJECT_ID"),
		Environment:   getEnv("ENVIRONMENT", "dev"),
		SiteOrigin:    mustEnv("SITE_ORIGIN"),
		ServiceURL:    getEnv("SERVICE_URL", ""),
		DispatchToken: mustEnv("DISPATCH_TOKEN"),
		MailerBackend: getEnv("MAILER_BACKEND", "gmail"),
		SMTP: smtpConfig{
			From: mustEnv("SMTP_FROM"), // From: header for both backends
		},
	}

	switch cfg.MailerBackend {
	case "gmail":
		cfg.Gmail.Subject = mustEnv("GMAIL_SUBJECT")
	case "smtp":
		cfg.SMTP.Host = mustEnv("SMTP_HOST")
		cfg.SMTP.Username = mustEnv("SMTP_USERNAME")
		cfg.SMTP.Password = mustEnv("SMTP_PASSWORD")
		port, err := strconv.Atoi(getEnv("SMTP_PORT", "587"))
		if err != nil {
			return nil, fmt.Errorf("SMTP_PORT: %w", err)
		}
		cfg.SMTP.Port = port
	default:
		return nil, fmt.Errorf("MAILER_BACKEND must be gmail or smtp, got %q", cfg.MailerBackend)
	}

	return cfg, nil
}
```

- [ ] **Step 4: Wire main.go backend selection**

In `cmd/notifier/main.go`, replace `mailer := newSMTPMailer(cfg.SMTP, logger)` with:

```go
	var m mailer
	switch cfg.MailerBackend {
	case "gmail":
		gm, err := newGmailMailer(ctx, cfg, logger)
		if err != nil {
			logger.Error("gmail mailer init failed", "err", err)
			os.Exit(1)
		}
		m = gm
	default:
		m = newSMTPMailer(cfg.SMTP, logger)
	}
```

and use `m` where `mailer` was passed (dispatcher `mailer: m`, server `mailer: m`). Note `ctx` already exists in `main` (the `signal.NotifyContext`).

- [ ] **Step 5: Run tests + build**

Run: `go test ./cmd/notifier/... && go build ./cmd/notifier/`
Expected: PASS + clean build.

- [ ] **Step 6: Commit**

```bash
git -C /Users/niels/Source/craftedsignal/threat-feed add cmd/notifier/config.go cmd/notifier/config_test.go cmd/notifier/main.go
git -C /Users/niels/Source/craftedsignal/threat-feed commit -m "feat(notifier): select mailer backend by MAILER_BACKEND (default gmail)"
```

---

### Task 5: Terraform — IAM, env vars, revert VPC egress

Grant the runtime SA token-creator on itself; set the Gmail env vars; remove the now-pointless VPC egress added earlier today.

**Files:**
- Modify: `infrastructure/terraform/modules/feed-notifier/main.tf`
- Modify: `infrastructure/terraform/modules/feed-notifier/variables.tf`
- Modify: `infrastructure/terraform/environments/prod/main.tf`

- [ ] **Step 1: Add self token-creator IAM + env vars in the module**

In `modules/feed-notifier/main.tf`, add near the service account resource (confirmed: the module defines the runtime SA as `google_service_account.notifier` at line ~63, used as the Cloud Run `service_account`):

```hcl
# Keyless domain-wide delegation: the runtime SA signs its own delegated
# Gmail tokens via the IAM Credentials API, so it needs tokenCreator on itself.
resource "google_service_account_iam_member" "notifier_self_token_creator" {
  service_account_id = google_service_account.notifier.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.notifier.email}"
}
```

Add two env vars to the container `env` block in `google_cloud_run_v2_service.notifier` (same style as the existing `env` entries):

```hcl
    env {
      name  = "MAILER_BACKEND"
      value = "gmail"
    }
    env {
      name  = "GMAIL_SUBJECT"
      value = var.gmail_subject
    }
```

- [ ] **Step 2: Add the module variable + prod value**

In `modules/feed-notifier/variables.tf`:

```hcl
variable "gmail_subject" {
  description = "DWD-impersonated Workspace user the notifier sends as (real mailbox; From: header uses the alias smtp_from)."
  type        = string
}
```

In `environments/prod/main.tf`, inside the `module "feed_notifier"` block:

```hcl
  gmail_subject = "nhofmans@craftedsignal.io"
```

- [ ] **Step 3: Revert the VPC-egress additions**

Remove the `vpc_access` block from `google_cloud_run_v2_service.notifier` and the `vpc_network`/`vpc_subnet` variables in `modules/feed-notifier/`, and the `vpc_network`/`vpc_subnet` lines in `environments/prod/main.tf` (added earlier today). HTTPS to `googleapis.com` works over default egress.

- [ ] **Step 4: Format + validate**

Run:
```bash
cd /Users/niels/Source/craftedsignal/infrastructure/terraform
terraform fmt -recursive modules/feed-notifier environments/prod
cd environments/prod && terraform validate
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 5: Commit**

```bash
git -C /Users/niels/Source/craftedsignal/infrastructure add terraform/modules/feed-notifier terraform/environments/prod/main.tf
git -C /Users/niels/Source/craftedsignal/infrastructure commit -m "feat(feed-notifier): Gmail API mailer (keyless DWD); revert VPC egress"
```

---

### Task 6: Deploy + end-to-end verify

**Prerequisite (user, one-time):** Google Admin → Security → API controls → Domain-wide delegation → Add: Client ID `112753602460856002671`, scope `https://www.googleapis.com/auth/gmail.send`. Without this, sends return `401 unauthorized_client`.

**Files:** none (build/deploy).

- [ ] **Step 1: Build + push the image**

The image builds from `threat-feed/Dockerfile.notifier` (confirmed present). Prefer triggering the repo's normal image CI; to build manually:

```bash
cd /Users/niels/Source/craftedsignal/threat-feed
gcloud auth configure-docker europe-west1-docker.pkg.dev -q
docker build -f Dockerfile.notifier -t europe-west1-docker.pkg.dev/craftedsignal-shared/craftedsignal/feed-notifier:latest .
docker push europe-west1-docker.pkg.dev/craftedsignal-shared/craftedsignal/feed-notifier:latest
```
Expected: build SUCCESS, image pushed.

- [ ] **Step 2: Apply infra (env vars + IAM + egress revert) via the normal path**

Deploy Terraform through the standard `deploy-infra.yml` (env `prod`, action `apply`) so the env vars, the self token-creator binding, and the egress removal land together. (Verify `plan` shows: +2 env vars, +1 iam_member, -vpc_access.)

- [ ] **Step 3: Confirm the running revision picked up the new image + env**

Run:
```bash
gcloud run services describe feed-notifier-prod --region=europe-west1 \
  --format="value(status.latestReadyRevisionName)"
gcloud run services describe feed-notifier-prod --region=europe-west1 --format=json \
  | python3 -c "import sys,json;c=json.load(sys.stdin)['spec']['template']['spec']['containers'][0];print({e['name']:e.get('value') for e in c['env'] if e['name'] in ('MAILER_BACKEND','GMAIL_SUBJECT','SMTP_FROM')})"
```
Expected: `MAILER_BACKEND=gmail`, `GMAIL_SUBJECT=nhofmans@craftedsignal.io`, `SMTP_FROM=feed-noreply@craftedsignal.io`.

- [ ] **Step 4: End-to-end send test**

Run:
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://notify.craftedsignal.io/subscribe \
  -H "Content-Type: application/json" \
  -d '{"channel":"email","email":"nhofmans@craftedsignal.io","filter":{}}'
```
Expected: `202`. Then confirm a verification email arrives from `feed-noreply@craftedsignal.io`, and logs show no `gmail send failed`:
```bash
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="feed-notifier-prod" AND jsonPayload.msg=~"gmail|mail"' --limit=5 --freshness=5m --format="value(timestamp,jsonPayload.msg,jsonPayload.err)"
```
Expected: empty or non-error.

- [ ] **Step 5: Update memory**

Append to `feed-notifier-smtp-egress.md`: resolved by moving to Gmail API + keyless DWD (SA `feed-notifier-prod@…` self-tokenCreator, subject `nhofmans@`, From `feed-noreply@`, client ID `112753602460856002671` authorized for gmail.send); SMTP path retained behind `MAILER_BACKEND=smtp` for local dev only.

---

## Self-Review

**Spec coverage:** gmailMailer over interface (T2) ✓; keyless DWD auth (T3) ✓; reuse MIME builder (T1) ✓; config `GMAIL_SUBJECT`/`MAILER_BACKEND`, From=alias, subject=real user (T4) ✓; IAM tokenCreator-on-self (T5) ✓; env vars in TF (T5) ✓; revert VPC egress (T5) ✓; DWD admin step + verify (T6) ✓; SMTP retained for dev (T4) ✓. No gaps.

**Placeholder scan:** No TBD/TODO; every code step shows full code; Task 6 build step names the exact image and a concrete command (confirm the repo's Dockerfile path at execution).

**Type consistency:** `rawSender.Send(userID, raw string) error` used identically in T2 (fake) and T3 (`gmailAPISender`); `newGmailMailerWith` (T2) consumed by `newGmailMailer` (T3); `buildRFC822(from, msg)` defined T1, used T1+T2; `config.Gmail.Subject` defined T4, used T3. Consistent.
