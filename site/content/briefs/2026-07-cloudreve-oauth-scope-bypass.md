---
title: Cloudreve OAuth Access Token Scope Bypass Vulnerability
slug: 2026-07-cloudreve-oauth-scope-bypass
description: Cloudreve's OAuth implementation contains a vulnerability, CVE-2026-54560, where OAuth access tokens bypass intended scope enforcement due to a missing `client_id` claim, allowing an attacker with a low-scope token to access sensitive APIs requiring higher privileges, effectively leading to privilege escalation.
date: "2026-07-20T21:19:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - oauth
  - vulnerability
  - privilege-escalation
  - cloudreve
  - web-application
vendors:
  - Cloudreve
products:
  - Cloudreve (>= 4.0.0-20260114075425-bc6845bd742c, < 4.0.0-20260606015557-ed20843dc3df)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A low-scope OAuth access token, for example one granted only `openid`, can call APIs requiring higher scopes such as file, share, workflow, user setting, WebDAV account, and potentially admin scopes when the authorizing user is an administrator.
    confidence_band: high
cves:
  - id: CVE-2026-54560
    cvss: 7.6
    epss: 0.00247
references:
  - https://github.com/advisories/GHSA-vgj4-345g-jcf8
  - CVE-2026-54560
---

A high-severity vulnerability, CVE-2026-54560, has been identified in Cloudreve versions `>= 4.0.0-20260114075425-bc6845bd742c` and `< 4.0.0-20260606015557-ed20843dc3df`, which allows OAuth access tokens to bypass intended scope enforcement. This flaw occurs because OAuth access tokens are issued without the `client_id` claim. Consequently, Cloudreve's JWT verifier fails to load the specified scopes into the request context. The `RequiredScopes(...)` middleware then incorrectly treats these requests as non-scoped, session-based authentications, effectively skipping all scope checks. This enables an attacker, holding a legitimate but low-scope OAuth access token (e.g., granted only `openid`), to access sensitive APIs that normally require higher privileges, such as file management, sharing, workflow controls, user settings, WebDAV account management, and potentially even administrative functions if the authorizing user possesses administrative rights. This vulnerability represents a significant privilege escalation risk for affected Cloudreve deployments.

## Attack Chain

1. An attacker creates or utilizes an existing third-party OAuth client configured with a minimal scope, such as `openid`.
2. The attacker convinces a legitimate Cloudreve user to authorize this OAuth application for the specified low-privilege scope.
3. Upon user authorization, Cloudreve issues an authorization code to the OAuth application.
4. The attacker's OAuth application exchanges this authorization code for an access token by sending a `POST` request to `/api/v4/session/oauth/token`.
5. Cloudreve's `Issue(...)` function generates the access token, embedding the requested scopes but inadvertently omitting the `ClientID` claim in the JWT payload.
6. The attacker uses this compromised access token as a bearer token (`Authorization: Bearer <access_token>`) to authenticate subsequent API requests.
7. When an API request arrives, Cloudreve's JWT verifier attempts to load scopes into the request context. However, because the access token lacks the `ClientID` claim, the scopes are not loaded.
8. The `RequiredScopes(...)` middleware, designed to enforce API access based on scopes, proceeds to check for scopes in the request context. Finding none (due to the missing `ClientID`), it incorrectly skips scope enforcement entirely, treating the request as a non-scoped session-based authentication.
9. As a result, API calls requiring higher scopes (e.g., `Files.Read/Write`, `Shares.Read/Write`, `UserInfo.Write`, `DavAccount.Write`, or even `Admin.Read/Write`) are processed and executed successfully under the authorizing user's identity, bypassing the intended OAuth scope restrictions.

## Impact

This vulnerability does not enable anonymous authentication bypass but allows for a critical OAuth consent and scope boundary bypass. An attacker leveraging this flaw requires a valid OAuth access token for a real user, albeit one initially granted minimal permissions (e.g., `openid`). Once obtained, this low-privilege token can be illicitly used to perform actions typically restricted to much higher scopes on behalf of the user. For regular users, this could lead to unauthorized access, modification, or deletion of files, shares, workflows, user settings, and WebDAV account/device configurations. If the authorizing user possesses administrative privileges, the same flaw can be exploited to access and manipulate administrator-scoped functionality without the OAuth application ever being explicitly granted `Admin.Read` or `Admin.Write` scopes, leading to severe unauthorized administrative control.

## Recommendation

* Patch Cloudreve installations immediately to a version that addresses CVE-2026-54560, specifically versions equal to or greater than `4.0.0-20260606015557-ed20843dc3df`.
* Monitor application logs and API gateway logs for unusual access patterns by OAuth tokens, particularly calls to sensitive endpoints (`Files`, `Shares`, `Workflow`, `User`, `DavAccount`, `Admin` APIs) made by tokens initially granted minimal scopes.
* Implement API gateway or proxy-level checks to validate OAuth scopes against API endpoint requirements, ensuring a fail-closed approach for all OAuth token-based requests.
* Regularly audit all registered OAuth clients within Cloudreve, reviewing their granted permissions and their necessity.
