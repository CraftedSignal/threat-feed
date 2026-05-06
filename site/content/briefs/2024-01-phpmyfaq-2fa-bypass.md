---
title: phpMyFAQ Unauthenticated 2FA Brute-Force Vulnerability
slug: 2024-01-phpmyfaq-2fa-bypass
description: phpMyFAQ is vulnerable to an unauthenticated 2FA brute-force attack via the `/admin/check` endpoint, allowing attackers to bypass two-factor authentication and gain administrative access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - phpMyFAQ
  - 2FA Bypass
  - Brute-Force
  - Authentication
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ (<= 4.1.1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://github.com/advisories/GHSA-9pq7-mfwh-xx2j
iocs:
  - type: url
    value: http://target.example/admin/check
ioc_counts:
  url: 1
rules:
  - title: phpMyFAQ Unauthenticated 2FA Brute-Force Attempt
    description: Detects attempts to brute-force 2FA in phpMyFAQ by monitoring POST requests to the /admin/check endpoint without prior authentication.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - webserver
      - linux
  - title: phpMyFAQ Successful Unauthenticated 2FA Bypass
    description: Detects successful unauthenticated 2FA bypass in phpMyFAQ by monitoring for HTTP 302 redirects after a POST request to /admin/check.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

phpMyFAQ versions 4.1.1 and earlier are susceptible to an unauthenticated two-factor authentication (2FA) bypass vulnerability. The vulnerability exists in the `/admin/check` endpoint, which is intended for validating TOTP codes. Due to the `SkipsAuthenticationCheck` implementation, this endpoint can be accessed without prior password authentication. An attacker can send POST requests with arbitrary `user-id` and `token` values, attempting to brute-force the 6-digit TOTP code. The absence of rate limiting allows an attacker to exhaust the keyspace relatively quickly. Successful exploitation grants a fully authenticated administrative session, enabling complete control over the application. This poses a significant risk to the confidentiality, integrity, and availability of the phpMyFAQ instance and its data.

## Attack Chain

1.  Attacker identifies a valid `user-id`, often starting with common values like 1 for the admin user.
2.  Attacker sends a POST request to `/admin/check` with a guessed 6-digit TOTP code and the target `user-id`.
3.  The `/admin/check` endpoint processes the request without verifying prior password authentication due to the `SkipsAuthenticationCheck` interface.
4.  The application validates the provided TOTP code against the user ID.
5.  If the TOTP is incorrect, the server redirects to `/admin/token?user-id=<user_id>`.
6.  The attacker iterates through possible TOTP codes (000000-999999) in a loop.
7.  Upon successful TOTP validation, `twoFactorSuccess()` is called, creating an authenticated admin session.
8.  The server redirects to `./`, granting the attacker full administrative access to phpMyFAQ. The attacker can now perform actions like user management, data exfiltration, and configuration changes.

## Impact

Successful exploitation allows an attacker to bypass 2FA for any user account, including administrators, without knowing the user's password. This results in full administrative control over the phpMyFAQ instance, potentially leading to unauthorized data access, modification, or deletion. The attacker can manage users, modify FAQ content, change configurations, and access backup/export functions containing all data. Given the ease of exploitation due to the lack of rate limiting, a wide range of phpMyFAQ instances are at risk.

## Recommendation

*   Deploy the Sigma rule "phpMyFAQ Unauthenticated 2FA Brute-Force Attempt" to your SIEM to detect attempts to exploit this vulnerability by monitoring POST requests to `/admin/check` (logsource: webserver).
*   Apply a rate limit or account lockout policy on the `/admin/check` endpoint to prevent brute-force attacks.
*   Implement session binding in the `check()` action to ensure that TOTP validation only occurs after successful password authentication, as described in the Recommended Fix section of the overview.
*   Upgrade to a patched version of phpMyFAQ that addresses this vulnerability, if available.
