---
title: '9router: Login Brute-Force Protection Bypass via Spoofed X-Forwarded-For Header'
slug: 2026-07-9router-x-forwarded-for-bypass
description: The 9router dashboard login rate limiter incorrectly uses the attacker-controlled X-Forwarded-For HTTP header to identify clients, leading to a brute-force protection bypass (CVE-2026-55501) that allows attackers to circumvent the lockout mechanism and conduct unlimited password brute-force attempts to gain administrative access.
date: "2026-07-06T21:49:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - brute-force
  - rate-limit-bypass
  - x-forwarded-for
  - vulnerability
  - web-application
vendors:
  - 9router
products:
  - 9router (<= 0.4.71)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: An attacker can continue brute-force attempts without triggering the configured lockout.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: An attacker can continue brute-force attempts without triggering the configured lockout.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7cfm-pqrj-xgq7
rules:
  - title: Detect 9router Dashboard Brute-Force Attempts
    description: Detects CVE-2026-55501 exploitation — A high volume of failed login attempts to the 9router dashboard login endpoint, indicative of a brute-force attack facilitated by the X-Forwarded-For bypass vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
rules_count: 1
---

A high-severity vulnerability (CVE-2026-55501) has been identified in the 9router dashboard, specifically in versions up to and including 0.4.71. This flaw stems from the application's reliance on the attacker-controlled `X-Forwarded-For` HTTP header to determine a client's identity for its login rate-limiting mechanism. When 9router is exposed directly to the internet or deployed behind a reverse proxy that does not properly overwrite untrusted `X-Forwarded-For` headers, a remote attacker can bypass the brute-force protection. By rotating the `X-Forwarded-For` value with each login attempt, the attacker receives a fresh rate-limit bucket, rendering the lockout mechanism ineffective. This enables unlimited password guessing against the dashboard, significantly increasing the risk of unauthorized administrative access, especially if default or weak credentials are in use.

## Attack Chain

1.  A remote attacker identifies a publicly reachable 9router dashboard instance, typically listening on HTTP/S.
2.  The attacker initiates a series of login attempts by sending HTTP `POST` requests to the `/api/auth/login` endpoint.
3.  For each login attempt, the attacker crafts a unique and arbitrary `X-Forwarded-For` HTTP header value (e.g., `10.0.0.1`, `10.0.0.2`, `10.0.0.3`).
4.  The 9router application, due to its vulnerable `getClientIp` function, uses this attacker-controlled `X-Forwarded-For` value as the client identifier for its in-memory rate limiter.
5.  Each unique `X-Forwarded-For` header creates a new, independent rate-limit bucket for the attacker, effectively resetting the failed attempt counter and bypassing the configured lockout thresholds.
6.  The attacker continues this process, performing unlimited password guessing against the dashboard login without triggering any lockout, until the correct credentials are found or all possibilities are exhausted.

## Impact

Successful exploitation of CVE-2026-55501 allows an attacker to completely bypass the 9router dashboard's login lockout mechanism, enabling unlimited brute-force attempts against user passwords. If the attacker successfully guesses credentials, particularly in instances still using default or weak passwords, they gain administrative access to the 9router dashboard. This administrative access could lead to severe consequences, including the ability to retrieve sensitive configured provider credentials and API keys, modify critical application settings, disable security features, create persistent backdoors via new API keys, or further pivot into other connected systems by chaining with additional server-side functionality exposed by the dashboard.

## Recommendation

*   Immediately patch 9router to a version greater than 0.4.71 to address CVE-2026-55501.
*   If patching is not immediately possible, ensure that 9router is deployed behind a trusted reverse proxy (e.g., Nginx, Apache, Caddy) that is configured to overwrite or remove untrusted `X-Forwarded-For` headers originating from external networks.
*   Implement strong, complex, and unique passwords for all 9router dashboard accounts, and enforce multi-factor authentication (MFA) if available, as a layered defense against credential-based attacks.
*   Deploy the Sigma rule "Detect 9router Dashboard Brute-Force Attempts" in this brief to your SIEM to identify sustained failed login activity targeting the `/api/auth/login` endpoint.
