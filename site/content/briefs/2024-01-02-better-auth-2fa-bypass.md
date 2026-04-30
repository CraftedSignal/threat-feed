---
title: Better Auth Two-Factor Authentication Bypass Vulnerability
slug: 2024-01-02-better-auth-2fa-bypass
description: Better Auth versions prior to 1.4.9 have a critical two-factor authentication bypass vulnerability; when session.cookieCache is enabled, the initial sign-in session may be improperly cached, allowing attackers with valid credentials to bypass 2FA.
date: "2026-04-03T03:29:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication
  - 2fa
  - bypass
  - better-auth
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/advisories/GHSA-xg6x-h9c9-2m83
rules:
  - title: Detect Better Auth 2FA Bypass Attempt via Session Cookie
    description: Detects potential attempts to exploit the Better Auth 2FA bypass vulnerability by monitoring for access to protected resources immediately after initial login, before the 2FA check can complete.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
  - title: Detect Better Auth Vulnerable Version Usage
    description: Detects the use of Better Auth versions prior to 1.4.9, which are vulnerable to 2FA bypass. Requires application-level logging of library versions.
    platform: sigma
    severity: medium
    tactics:
      - vulnerability
    data_sources:
      - application
      - linux
rules_count: 2
---

Better Auth versions prior to 1.4.9 contain a critical vulnerability that can lead to two-factor authentication (2FA) bypass. The vulnerability arises when the `session.cookieCache` is enabled. In this configuration, the initial session created during the login process can be prematurely cached before the 2FA verification is completed. Consequently, subsequent session lookups might use this cached session, circumventing the necessary 2FA check. This issue allows an attacker who possesses valid primary credentials to gain unauthorized access to protected application routes without completing the mandated second authentication factor. Any application leveraging `better-auth` with 2FA and session cookie caching enabled is potentially vulnerable.

## Attack Chain

1. User attempts to log in with valid username and password.
2. The application, running a vulnerable version of `better-auth` with `session.cookieCache` enabled, creates a session.
3. The session is cached due to the `session.cookieCache` setting, *before* the 2FA challenge is presented.
4. The user is prompted for their second factor (e.g., TOTP code).
5. Instead of providing the 2FA code, the attacker intercepts or reuses the cached session cookie.
6. The attacker presents the cached session cookie to the application.
7. The application retrieves the cached session, which it prematurely considers valid.
8. The attacker gains access to protected resources without completing 2FA.

## Impact

Successful exploitation of this vulnerability allows attackers with valid usernames and passwords to bypass two-factor authentication, gaining unauthorized access to sensitive application resources. The number of affected applications is unknown, but all applications using `better-auth` with 2FA and session caching are potentially at risk. A successful attack could lead to data breaches, account takeovers, and other serious security incidents.

## Recommendation

*   Upgrade to `better-auth` version 1.4.9 or later to patch the vulnerability.
*   Disable `session.cookieCache` when using two-factor authentication as a temporary mitigation.
*   If disabling `session.cookieCache` is not feasible, implement server-side checks to ensure 2FA is completed before granting full session validity (requires code modification).
