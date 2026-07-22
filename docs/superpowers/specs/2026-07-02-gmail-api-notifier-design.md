# feed-notifier: send email via Gmail API (replace SMTP)

**Date:** 2026-07-02
**Status:** Draft — awaiting user approval + two open decisions (see end)
**Component:** `threat-feed/cmd/notifier` (Cloud Run `feed-notifier-prod`)

## Problem

`/subscribe` returns `HTTP 502 "email send failed"`. Root cause (fully diagnosed 2026-07-02): Gmail's SMTP relay drops **SMTP AUTH from GCP-origin connections** — the notifier's Cloud Run egress can't authenticate (`auth: EOF`), while the same credentials succeed from a residential IP. Routing via VPC + Cloud NAT static IP did not help: traffic to Google's own destination IPs never traverses Cloud NAT, so the allow-listed IP is never presented, and GCP-origin SMTP is blocked at a layer the Workspace relay allow-list doesn't govern. Four SMTP-level fixes (auth identity, new App Password, VPC/NAT egress, relay IP allow-list) confirmed SMTP-from-serverless is a dead end.

## Goal

Send the verification / notification emails reliably from Cloud Run, sending **as `feed-noreply@craftedsignal.io`**, with minimal blast radius and no fragile credentials.

## Approach (recommended): Gmail API over HTTPS with keyless domain-wide delegation

HTTPS to `gmail.googleapis.com` is not subject to the SMTP egress block. The Cloud Run runtime service account uses **domain-wide delegation (DWD)** to act as a Workspace user and send as the `feed-noreply@` alias.

- **Auth (keyless):** `google.golang.org/api/impersonate.CredentialsTokenSource` with base credentials = ADC (the runtime SA `feed-notifier-prod@craftedsignal-prod.iam.gserviceaccount.com`), `TargetPrincipal` = that same SA, `Subject = nhofmans@craftedsignal.io`, `Scopes = [gmail.GmailSendScope]`. Signing goes through the IAM Credentials API — **no key file**. (`feed-noreply@` is only an alias, so it can't be the DWD subject; the real user `nhofmans@` is the subject and the `From:` header carries the alias.)
- **Send:** build the RFC822 message, base64url-encode, call `gmail.Users.Messages.Send("me", &gmail.Message{Raw: ...})`.

### Components

- **`gmail_mailer.go` (new)** — `gmailMailer` implementing the existing `mailer` interface (`Send`, `SendBatch`). `SendBatch` loops `Send` (no persistent connection to amortize anymore; Gmail API per-user send quota is ample for this volume). Depends on: `google.golang.org/api/gmail/v1`, `google.golang.org/api/impersonate`, `google.golang.org/api/option` (all under the already-present `google.golang.org/api v0.283.0`).
- **Shared message formatting** — extract the existing MIME builder (`formatMessage`/`writeHeader`/`quotedPrintable`/`mimeBoundary`) into a package-level `buildRFC822(from string, msg SmtpMessage) string` reused by both mailers. No behavior change to the message format.
- **`config.go`** — add `GMAIL_SUBJECT` (impersonated real user, `nhofmans@`) and keep `SMTP_FROM` as the `From:` address. Add `MAILER_BACKEND` (`gmail` default; `smtp` retained for local/dev e.g. Mailhog). SMTP_* become required only when backend=smtp.
- **`main.go`** — construct `gmailMailer` when backend=gmail; `smtpMailer` otherwise. `handlers.go` and `dispatcher.go` are unchanged (interface preserved).

### Infra / IAM (Terraform, `modules/feed-notifier` + `environments/prod`)

- Grant runtime SA `roles/iam.serviceAccountTokenCreator` **on itself** (to sign its own delegated tokens).
- Add env vars `MAILER_BACKEND=gmail`, `GMAIL_SUBJECT=nhofmans@craftedsignal.io`.
- **Revert the VPC-egress change** added earlier today (live rev 00026 + the `vpc_access` block, `vpc_network`/`vpc_subnet` vars, and prod wiring) — HTTPS to `googleapis.com` works over default Cloud Run egress; the VPC/NAT path is now pointless.
- SMTP secret/username Terraform can stay (backend=smtp fallback) but is no longer on the hot path.

### Manual step (user, one-time) — Google Admin → Security → API controls → Domain-wide delegation → Add new
- **Client ID:** `112753602460856002671`
- **Scope:** `https://www.googleapis.com/auth/gmail.send`
- Confirm `feed-noreply@` is a send-as/alias of `nhofmans@` (Gmail will only set that `From:` if so).

### Verification
- `/subscribe` → `202` and a real verification email delivered, `From: feed-noreply@craftedsignal.io`.
- Confirm no `smtp`/`auth` errors in logs; confirm `From` header + deliverability (SPF/DKIM already pass for the domain via Workspace).

### Rollback
- Revert to `MAILER_BACKEND=smtp` (config only) — but SMTP is known-broken from GCP, so real rollback = redeploy previous image. The change is additive (new mailer behind a flag), so low risk.

## Alternatives considered
- **SA-key DWD** — same result, but a long-lived key JSON to store in Secret Manager and rotate/guard. Rejected in favor of keyless (open decision below).
- **Third-party provider (SendGrid/Mailgun/Resend)** — robust HTTPS, but new vendor, API-key secret, and SPF/DKIM DNS. Rejected: keeps identity in existing Workspace, no new vendor.
- **Stored OAuth refresh token for feed-noreply@** — fragile (consent/expiry), and the alias has no independent login. Rejected.

## Open decisions (need user input before implementation)
1. **DWD feasibility** — can domain-wide delegation be enabled in Workspace admin? Required for this approach. If locked org-wide → pivot to a third-party provider.
2. **Keyless vs SA-key** — spec assumes **keyless** (recommended). If you want SA-key, the auth section changes to a Secret Manager key + `google.golang.org/api/option.WithCredentialsFile`, plus a `google_secret_manager_secret{,_version}` in Terraform.
