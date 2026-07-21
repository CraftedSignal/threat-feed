---
title: Gitea OAuth Callback Re-enables Administrator-Disabled Accounts
slug: 2026-07-gitea-oauth-reenable
description: An improper authorization vulnerability in Gitea's OAuth2 sign-in callback mechanism (CVE-2026-58422) allows users with linked external identity providers to unilaterally re-enable their administrator-disabled accounts, regaining full access and bypassing security controls.
date: "2026-07-21T21:52:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - improper-authorization
  - oauth
  - account-takeover
  - persistence
  - vulnerability
vendors:
  - Gitea Ltd
products:
  - Gitea (All versions prior to 1.26.4)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Once a user has linked any external IdP, the administrator's disable toggle becomes non-binding — the user can re-enable themselves on demand by completing one OAuth callback, regaining full read and write access to their repositories, organizations, and access tokens.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: the user can re-enable themselves on demand by completing one OAuth callback, regaining full read and write access to their repositories, organizations, and access tokens.
    confidence_band: high
cves:
  - id: CVE-2026-58422
    cvss: 9.8
    epss: 0.00343
references:
  - https://github.com/advisories/GHSA-g9g6-qhrc-p3qc
---

A high-severity improper authorization vulnerability, identified as CVE-2026-58422, affects Gitea versions prior to 1.26.4. This flaw allows users whose accounts have been disabled by an administrator to bypass this restriction and regain full access to their Gitea repositories, organizations, and access tokens. The vulnerability resides within the OAuth2 sign-in callback functionality, specifically in the `handleOAuth2SignIn` function. When a user with a previously linked external identity provider attempts to authenticate through OAuth2, the Gitea application logic incorrectly re-enables their locally disabled account and grants them a fresh authenticated session. This effectively nullifies administrator-initiated account disablement, posing a significant risk to incident response efforts, especially in environments relying on account deactivation for compromised or departed user scenarios.

## Attack Chain

1. An administrator configures an OAuth2 authentication source within Gitea, linking it to an external Identity Provider (IdP).
2. A user, e.g., "Alice," signs into Gitea at least once via this OAuth2 source, establishing a link between her local Gitea account and the external IdP.
3. A Gitea administrator subsequently disables Alice's account through the `Site Administration` panel, setting her `IsActive` flag to `false`.
4. Alice attempts to sign in again using the previously linked external IdP, triggering the OAuth2 authentication flow.
5. The Gitea application's `/user/oauth2/{source-name}/callback` endpoint processes the authentication request.
6. Within the `routers/web/auth/oauth.go::handleOAuth2SignIn` function, the application reads the user's `IsActive` flag and, despite it being `false`, incorrectly sets `opts.IsActive = optional.Some(true)`.
7. The `user_service.UpdateUser` function is called, which updates Alice's account in the database, effectively re-enabling it without administrative approval.
8. Gitea issues a new authenticated session to Alice, granting her full read and write access to her repositories, organizations, and tokens, bypassing the administrator's disable action.

## Impact

This vulnerability allows users to circumvent administrative account disablement, leading to unauthorized access and persistence. In organizations utilizing Gitea, particularly those integrated with Single Sign-On (SSO) systems where account disablement is a critical incident response measure for compromised credentials or employee departures, this flaw completely undermines security protocols. Affected Gitea deployments risk former employees or attackers with compromised external IdP access continuously regaining access, leading to data exfiltration, unauthorized code commits, or other malicious activities, even after an administrator has attempted to revoke access.

## Recommendation

* Patch Gitea installations to version 1.26.4 or later immediately to address CVE-2026-58422.
* Review audit logs for `UpdateUser` actions originating from OAuth callback processes for users previously disabled by an administrator.
* Consider implementing out-of-band monitoring for unexpected account re-activations, especially for accounts marked as disabled.
