---
title: Auth.js (next-auth) v5 Configuration Error Leads to Authentication Bypass
slug: 2026-07-authjs-fail-open
description: A critical configuration error vulnerability in `next-auth` (Auth.js) v5 applications, specifically versions v5.0.0-beta.0 through v5.0.0-beta.31, can lead to a 'fail-open' state where server-side configuration issues cause the `auth` object to be populated with an error instead of `null`, effectively bypassing authentication checks and granting unauthorized access to protected resources.
date: "2026-07-23T14:59:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - configuration-error
  - web-application
  - security-vulnerability
vendors:
  - Auth.js
products:
  - next-auth v5.0.0-beta.0 to v5.0.0-beta.31
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: 'Because this object is truthy, any authorization check of the form `!!auth` (or `if (req.auth)`) evaluates to `true` for **every** request, including unauthenticated ones. The application *fails open*: instead of denying access when the auth layer is broken, it grants access to everyone.'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: 'Because this object is truthy, any authorization check of the form `!!auth` (or `if (req.auth)`) evaluates to `true` for **every** request, including unauthenticated ones. The application *fails open*: instead of denying access when the auth layer is broken, it grants access to everyone.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8fpg-xm3f-6cx3
  - https://authjs.dev/getting-started/session-management/protecting
  - https://authjs.dev/guides/role-based-access-control
  - https://authjs.dev/reference/core/errors
  - https://authjs.dev/security
---

Auth.js (next-auth) v5 applications are affected by a critical configuration error vulnerability, GHSA-8fpg-xm3f-6cx3, where misconfigurations can lead to a "fail-open" state, bypassing authentication. This issue, first published on July 23, 2026, impacts versions `v5.0.0-beta.0` through `v5.0.0-beta.31`. When server-side configuration errors occur, such as missing OAuth provider settings or an unset `AUTH_SECRET`, the `auth` object, typically used to gate access, is erroneously populated with an error object instead of being `null`. This truthy error object causes common session existence checks (e.g., `if (req.auth)`) to evaluate as true for all incoming requests, including unauthenticated ones. Consequently, the application grants unauthorized access to protected resources, treating all visitors as authenticated. This silent failure mode poses a severe risk as it effectively renders authentication mechanisms useless without immediate detection.

## Attack Chain

1. An Auth.js `next-auth` v5 application is deployed, utilizing existence-based session checks (e.g., `if (req.auth)` or `!!auth`) in middleware or route handlers to protect resources.
2. A server-side configuration error occurs within the Auth.js setup, such as an incomplete OAuth provider configuration (e.g., missing `issuer` or `authorization` endpoints for Keycloak) or an unset `AUTH_SECRET` environment variable.
3. This misconfiguration causes Auth.js to log an internal error (e.g., `[auth][error] InvalidEndpoints`) and populate the `auth` object, typically used for session data, with an error object instead of `null`.
4. When the application's middleware or route handlers perform a session check (e.g., `const isLoggedIn = !!auth`), the truthy error object causes `isLoggedIn` to evaluate as `true`.
5. All subsequent requests, including those from unauthenticated users, are treated as if they possess a valid session.
6. The application "fails open," granting unauthorized access to protected resources and routes that were intended for authenticated users only.
7. This authentication bypass occurs silently, as the application behaves as if a valid session exists for every request, potentially leading to widespread unauthorized access without explicit error indications to the user or administrators.

## Impact

This vulnerability, an instance of CWE-636 (Not Failing Securely / "Failing Open") leading to improper authorization (CWE-285), can lead to severe consequences. If an affected application becomes misconfigured, all protected resources become openly accessible to anyone, regardless of authentication status. The failure is silent, meaning administrators may not be immediately aware that their authentication mechanisms are bypassed. This could result in unauthorized data exposure, manipulation, or complete compromise of systems, impacting confidentiality, integrity, and availability. While no specific victim count is provided, any organization using vulnerable `next-auth` versions with the described access pattern is at risk, particularly those with dynamic deployment environments where configuration changes are frequent.

## Recommendation

* Upgrade `next-auth` to the patched version (`next-auth@beta` or later stable release) immediately to ensure configuration errors fail closed.
* Modify existing session checks in `next-auth` middleware and route handlers to explicitly check for a user or session property (e.g., `!!req.auth?.user`) instead of just `!!req.auth` to prevent misconfiguration from being treated as a valid session.
* Implement robust deployment pipeline checks to monitor for `[auth][error]` log messages from your application, treating them as critical failures to prevent misconfigured applications from reaching production environments.
