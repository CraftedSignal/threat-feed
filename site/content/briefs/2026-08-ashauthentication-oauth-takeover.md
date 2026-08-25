---
title: 'CVE-2026-49757: AshAuthentication OAuth2/OIDC Account Takeover'
slug: 2026-08-ashauthentication-oauth-takeover
description: AshAuthentication incorrectly uses email addresses to link OAuth2/OIDC identities to local accounts, enabling unauthenticated account takeover via identity providers that allow unverified or reclaimed emails.
date: "2026-08-25T18:48:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - account-takeover
  - cve-2026-49757
  - oauth
  - oidc
  - authentication-bypass
vendors:
  - Team Alembic
products:
  - AshAuthentication
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: An unauthenticated attacker who can register an account on any accepted OAuth provider with the victim's email obtains the victim's full local privileges.
    confidence_band: high
cves:
  - id: CVE-2026-49757
    epss: 0.00615
references:
  - https://github.com/advisories/GHSA-777c-2fxx-qr28
  - https://github.com/team-alembic/ash_authentication/commit/c5f589058e04239263f50a1430eb17ea6d5dd1a2
  - https://github.com/team-alembic/ash_authentication/commit/728b8d28c1b5f465fa1116ef044a815300fc733d
  - https://github.com/team-alembic/ash_authentication/commit/64530644f9b37ebb76ca14aeb83a77597a0034b7
---

AshAuthentication, an authentication framework for Elixir/Ash applications, contains a critical vulnerability (CVE-2026-49757) in its OAuth2 and OpenID Connect (OIDC) implementation. The framework incorrectly relies on email addresses to identify users during the account registration and sign-in flow. By design, OIDC requires the use of the `iss` (issuer) and `sub` (subject) claim pair to uniquely and securely identify an end-user. AshAuthentication instead performed an upsert action based on the email address, allowing an attacker to register an identity on a third-party OAuth provider using a victim's email address. If the provider allows unverified emails, or if the email address has been reclaimed by the attacker, the application incorrectly maps the attacker's authentication session to the victim's existing local account. This flaw applies to versions 0.1.0 through 4.13.x and 5.0.0-rc.0 through 5.0.0-rc.9, granting attackers full privileges associated with the victim's account.

## Attack Chain

1. Attacker identifies a target application using the vulnerable AshAuthentication framework.
2. Attacker registers an account on an OAuth or OIDC identity provider, using the email address associated with the victim's account on the target application.
3. Attacker triggers the OAuth/OIDC registration flow on the target application.
4. The application's `AshAuthentication.Strategy.OAuth2.IdentityChange` module executes an upsert action, locating the victim's existing local record via the email identifier.
5. The `AshAuthentication.Strategy.OAuth2.SignInPreparation` module fails to validate the `iss` or `sub` claims, accepting the attacker's identity as valid for the linked local account.
6. The application completes the authentication handshake and generates a session token for the victim's account.
7. Attacker gains unauthorized access to the victim's local account, including read, write, and destructive capabilities.

## Impact

Successful exploitation allows for unauthenticated remote account takeover. Attackers can gain complete control over any victim's account, leading to unauthorized data access, modification, or account deletion within the affected application. Because the default configuration of the strategy is vulnerable, any application using these versions is exposed without needing misconfiguration by the site administrator.

## Recommendation

* Immediately upgrade AshAuthentication to version 4.14.0 or 5.0.0-rc.10 or later to patch CVE-2026-49757.
* Audit application logs for anomalous sign-ins involving OAuth providers that have historically allowed unverified email registrations.
* Review OAuth/OIDC provider configurations to ensure that email verification is strictly enforced and that account reuse policies are disabled where possible.
* Coordinate with application security teams to perform a post-patch review of authentication logs to identify any sessions initiated by potentially hijacked identities.
