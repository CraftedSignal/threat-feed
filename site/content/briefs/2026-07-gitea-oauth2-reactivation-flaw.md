---
title: Gitea OAuth2 Sign-in Flaw Reactivates Administrator-Deactivated Accounts
slug: 2026-07-gitea-oauth2-reactivation-flaw
description: A vulnerability (CVE-2026-55987) in Gitea's OAuth2 sign-in allows administrator-deactivated user accounts to be reactivated upon re-authentication through specific authentication sources (like GitHub or OIDC/OAuth2 without refresh tokens), enabling users to regain full access, potentially including administrator privileges, by bypassing the intended deactivation.
date: "2026-07-21T21:03:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - gitea
  - vulnerability
  - authentication
  - account-takeover
  - privilege-escalation
vendors:
  - Gitea
products:
  - go/code.gitea.io/gitea (versions prior to 1.27.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Deactivation does not clear `IsAdmin`, so a deactivated administrator regains admin access.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: defeats the `IsActive=false` deactivation only
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: A deactivated user restores their own account to active and obtains a session, regaining whatever access the account had.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-vrhc-jjfc-m3m3
---

A critical vulnerability, CVE-2026-55987, has been identified in Gitea versions prior to 1.27.0, where its OAuth2 sign-in callback function can inadvertently reactivate user accounts that an administrator had explicitly deactivated. This flaw stems from an incomplete fix (PR #38009) that incorrectly interprets an empty refresh token as a signal for auto-sync disabled accounts, rather than accounts deliberately deactivated by an administrator. This condition commonly occurs when Gitea instances are configured with GitHub as an authentication source, or with any OpenID Connect (OIDC) or OAuth2 provider that does not issue refresh tokens (i.e., configured without `offline_access`). A deactivated user can simply sign in again through these authentication methods, bypassing the administrator's security control and regaining full access to their previous Gitea session, which could include administrator privileges if the account previously held them. This undermines account management and access control within affected Gitea deployments.

## Attack Chain

1. The Gitea instance is configured with a GitHub OAuth2 authentication source or an OIDC/OAuth2 source without `offline_access`.
2. An administrator manually deactivates a user account by setting its `IsActive` status to `false` in the Gitea Admin Panel.
3. The deactivated user attempts to sign in to Gitea using the configured GitHub or OIDC/OAuth2 authentication source.
4. Gitea's `routers/web/auth/oauth.go` `handleOAuth2SignIn` function processes the authentication callback.
5. During this process, the function attempts to retrieve the user's `external_login_user` record, where the `refresh_token` field is legitimately empty for these specific OAuth2 sources.
6. The Gitea logic incorrectly interprets `extLogin.RefreshToken == ""` as a sign that the account was disabled by an auto-sync cron job, rather than by an administrator.
7. Consequently, Gitea sets the `IsActive` status of the user account back to `true`, reactivating it (`opts.IsActive = optional.Some(true)`).
8. The user successfully logs in and obtains a full, active Gitea session, regaining all previous access and privileges, thereby circumventing the administrator's deactivation.

## Impact

This vulnerability impacts any Gitea instance utilizing GitHub or OIDC/OAuth2 authentication sources without `offline_access` that relies on the "Activated" toggle for account deactivation. If exploited, an administrator-deactivated user account will be reactivated, granting the user full access to their previous session and resources. This means a former administrator, whose account was deactivated for security reasons, could regain their administrative privileges and potentially access sensitive code repositories, perform unauthorized actions, or compromise the Gitea instance. The flaw directly undermines access control mechanisms and could lead to unauthorized data manipulation, intellectual property theft, or further lateral movement within an organization's development infrastructure. The exact number of affected organizations is unknown, but Gitea is widely used by development teams globally.

## Recommendation

* Patch CVE-2026-55987 by upgrading all Gitea instances to version 1.27.0 or newer immediately, as specified in the advisory referenced in this brief.
* Implement monitoring for unexpected changes to the `is_active` status in the Gitea database for accounts that have been explicitly deactivated by an administrator.
* Review and audit all Gitea authentication sources, especially GitHub and OIDC/OAuth2 configurations, to understand which ones do not issue refresh tokens and are thus susceptible to this reactivation flaw.
