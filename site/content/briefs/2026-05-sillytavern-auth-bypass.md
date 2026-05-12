---
title: SillyTavern Authentication Bypass via HTTP Header Injection (CVE-2026-44649)
slug: 2026-05-sillytavern-auth-bypass
description: SillyTavern versions 1.17.0 and earlier are vulnerable to an authentication bypass (CVE-2026-44649) via HTTP header injection, where the application accepts Remote-User and X-Authentik-Username headers for SSO without proper validation, allowing attackers to impersonate any user, including administrators, if SSO is enabled.
date: "2026-05-12T22:24:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - header-injection
  - account-takeover
  - cve-2026-44649
vendors:
  - npm
products:
  - sillytavern (<= 1.17.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Personal Accounts
references:
  - https://github.com/advisories/GHSA-gxx6-h3g6-vwjh
  - https://docs.sillytavern.app/administration/sso/
rules:
  - title: Detect SillyTavern User Enumeration via /api/users/list
    description: Detects attempts to enumerate SillyTavern user accounts by accessing the publicly available /api/users/list endpoint.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1586.002
    data_sources:
      - webserver
  - title: Detect SillyTavern Authentication Bypass via Header Injection
    description: Detects CVE-2026-44649 exploitation — HTTP requests to the /login endpoint with injected Remote-User or X-Authentik-Username headers, indicating a possible authentication bypass attempt.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1586.002
    data_sources:
      - webserver
rules_count: 2
---

SillyTavern versions 1.17.0 and earlier contain an authentication bypass vulnerability related to Single Sign-On (SSO) header handling. When SSO is configured with Authelia or Authentik, the application trusts the `Remote-User` and `X-Authentik-Username` HTTP headers to automatically log in users. However, there's no validation to ensure these headers originate from a trusted reverse proxy. This lack of validation allows any network client capable of reaching the SillyTavern port to inject arbitrary headers and authenticate as any user, including administrators, without providing valid credentials. This vulnerability is only exploitable when `sso.autheliaAuth: true` or `sso.authentikAuth: true` is set in the `config.yaml` file. This issue was resolved in version 1.18.0 by introducing a configuration option to limit the IP addresses authorized to use SSO headers.

## Attack Chain

1. The attacker identifies a SillyTavern instance with SSO enabled for Authelia or Authentik (sso.autheliaAuth or sso.authentikAuth set to true in config.yaml).
2. The attacker sends a POST request to `/api/users/list` to enumerate valid usernames. This endpoint is publicly accessible.
3. The server responds with a JSON list of user handles, including administrator accounts.
4. The attacker crafts an HTTP request, injecting either the `Remote-User` or `X-Authentik-Username` header with the target username (e.g., "admin-user").
5. The attacker sends this crafted request to the `/login` endpoint.
6. The SillyTavern server's `headerUserLogin` function reads the injected header and creates an authenticated session for the specified user without any validation.
7. The attacker receives a valid session cookie (`authsession`).
8. The attacker retrieves a CSRF token from the `/csrf-token` endpoint using the session cookie.
9. The attacker can now access administrative endpoints (e.g., `/api/users/admin/get`) using the injected session and CSRF token.

## Impact

Successful exploitation leads to complete account takeover, enabling an attacker to perform any action authorized for the impersonated user, including accessing sensitive data, modifying configurations, and performing other administrative tasks.

## Recommendation

*   Upgrade to SillyTavern version 1.18.0 or later, which includes a configuration option to limit authorized IP addresses for SSO headers (see Resolution section in the advisory).
*   Apply the configuration to limit SSO header authorization to only loopback addresses (127.0.0.1) or trusted reverse proxy IPs, as documented in [https://docs.sillytavern.app/administration/sso/](https://docs.sillytavern.app/administration/sso/).
*   Deploy the Sigma rule "Detect SillyTavern User Enumeration via /api/users/list" to identify attempts to enumerate user accounts using the publicly accessible API endpoint.
*   Deploy the Sigma rule "Detect SillyTavern Authentication Bypass via Header Injection" to detect requests with injected Remote-User or X-Authentik-Username headers to the /login endpoint.
