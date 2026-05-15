---
title: phpMyFAQ Unauthenticated TOTP Bypass via Brute-Force (CVE-2026-45010)
slug: 2026-05-phpmyfaq-totp-bypass
description: phpMyFAQ before 4.1.2 is vulnerable to improper restriction of excessive authentication attempts in the /admin/check endpoint, allowing unauthenticated attackers to brute-force any user's six-digit TOTP code and bypass two-factor authentication, potentially gaining full administrative access (CVE-2026-45010).
date: "2026-05-15T19:19:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - brute-force
  - totp
  - phpMyFAQ
  - credential-access
  - authentication-bypass
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ (prior to 4.1.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
cves:
  - id: CVE-2026-45010
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45010
  - https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-9pq7-mfwh-xx2j
  - https://www.vulncheck.com/advisories/phpmyfaq-unauthenticated-two-factor-authentication-brute-force-via-admin-check-endpoint
rules:
  - title: Detect phpMyFAQ TOTP Brute-Force Attempts
    description: Detects CVE-2026-45010 exploitation — Excessive POST requests to /admin/check endpoint indicating potential TOTP brute-force
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - webserver
  - title: Detect phpMyFAQ admin/check endpoint access
    description: Detects access to /admin/check from suspicious client IP addresses that are not commonly seen.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - webserver
rules_count: 2
---

phpMyFAQ before version 4.1.2 is susceptible to an improper restriction of excessive authentication attempts. The vulnerability resides in the `/admin/check` endpoint, which lacks session binding and rate limiting. This endpoint accepts arbitrary user-id parameters, allowing unauthenticated attackers to target specific user accounts. By sending a series of POST requests with sequential token values, an attacker can brute-force the six-digit TOTP code of any user, effectively bypassing two-factor authentication. Successful exploitation allows the attacker to gain full administrative privileges within the phpMyFAQ application.

## Attack Chain

1.  The attacker identifies a phpMyFAQ instance running a version prior to 4.1.2.
2.  The attacker sends a POST request to `/admin/check` without any authentication.
3.  The POST request includes a `user-id` parameter specifying the target user account.
4.  The POST request also includes a `token` parameter containing a potential TOTP value.
5.  The attacker iterates through a range of six-digit numerical values for the `token` parameter.
6.  The server processes each request without rate limiting or session validation.
7.  Upon successful brute-force of the correct TOTP, the server grants administrative access.
8.  The attacker leverages the administrative access to modify data, create new accounts, or otherwise compromise the phpMyFAQ installation.

## Impact

A successful attack allows an unauthenticated attacker to gain full administrative access to the phpMyFAQ application. This can lead to complete compromise of the application's data, including sensitive information stored within the FAQ system. The attacker can also create new administrative accounts, further solidifying their control over the system. The potential impact includes data breaches, defacement, and denial of service.

## Recommendation

*   Upgrade phpMyFAQ to version 4.1.2 or later to patch CVE-2026-45010.
*   Implement rate limiting on the `/admin/check` endpoint to prevent brute-force attacks.
*   Deploy the Sigma rule "Detect phpMyFAQ TOTP Brute-Force Attempts" to identify potential brute-force attacks against the `/admin/check` endpoint.
*   Monitor web server logs for unusual activity targeting the `/admin/check` endpoint.
