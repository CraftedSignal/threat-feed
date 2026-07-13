---
title: 'FacturaScripts: Account takeover of any 2FA-enabled user due to authentication bypass'
slug: 2026-07-facturascripts-account-takeover
description: An authentication bypass vulnerability (CVE-2026-47677) in FacturaScripts' `/login?action=two-factor-validation` endpoint allows unauthenticated attackers to conduct a brute-force attack against Time-based One-Time Passwords (TOTP) for any 2FA-enabled user, including administrators, due to the absence of password verification, CSRF protection, and rate-limiting, leading to complete account takeover with high confidentiality and integrity impact, as well as potential denial of service via account lockout.
date: "2026-07-13T23:36:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - brute-force
  - 2fa-bypass
  - web-application
  - facturascripts
  - php
vendors:
  - FacturaScripts
products:
  - facturascripts (<= 2026.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'Authentication bypass in FacturaScripts: `/login?action=two-factor-validation` accepts brute-forceable TOTP without password or CSRF protection'
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: The endpoint therefore has no rate-limiting at all.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: If the TOTP value matches, the server issues a full `fsNick` + `fsLogkey` session cookie pair.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-c67f-gmxw-mj93
rules:
  - title: Detects CVE-2026-47677 Exploitation - FacturaScripts 2FA Endpoint Access
    description: Detects HTTP POST requests targeting the vulnerable two-factor authentication validation endpoint in FacturaScripts (`/login?action=two-factor-validation`), which is susceptible to brute-force attacks due to lack of rate-limiting, password verification, and CSRF protection. This rule identifies interaction with the vulnerable component.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1110
      - T1110.004
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Unauthenticated attackers can exploit an authentication bypass vulnerability, identified as CVE-2026-47677, in FacturaScripts' two-factor authentication (2FA) validation endpoint (`/login?action=two-factor-validation`). This flaw affects FacturaScripts versions up to and including 2026.2. The endpoint is designed to accept Time-based One-Time Passwords (TOTP) but critically lacks password verification, Cross-Site Request Forgery (CSRF) protection, and effective rate-limiting. This combination renders TOTP codes susceptible to brute-force attacks. Due to a lenient `VERIFICATION_WINDOW = 8`, approximately 17 distinct six-digit TOTP codes are simultaneously valid for a given user, significantly reducing the search space. A public Proof of Concept (PoC) demonstrates that an attacker, knowing only a target user's nickname (e.g., 'admin'), can successfully brute-force a valid TOTP code in minutes to an hour from a single IP address, leading to complete account takeover. This vulnerability grants attackers full access to compromised accounts, enabling high confidentiality and integrity impacts, and can also result in denial of service by locking legitimate users out of their accounts.

## Attack Chain

1. An unauthenticated attacker identifies a target FacturaScripts instance accessible via the network.
2. The attacker determines a valid username (`fsNick`) belonging to a 2FA-enabled account (e.g., 'admin', 'company_name', or user initials).
3. The attacker sends numerous HTTP POST requests to the `/login` endpoint, specifically targeting the `action=two-factor-validation` parameter.
4. Each POST request includes the target `fsNick` and an iterated 6-digit `fsTwoFactorCode` value.
5. The `twoFactorValidationAction()` endpoint processes these requests without requiring prior password authentication, validating a CSRF token, or applying rate-limiting, allowing for rapid brute-force attempts.
6. Due to the configured `TwoFactorManager::VERIFICATION_WINDOW = 8`, up to 17 TOTP codes are simultaneously valid for a single 30-second time slot, greatly facilitating the brute-force process.
7. Upon a successful guess of a valid `fsTwoFactorCode`, the server issues a complete session cookie pair (`fsNick` and `fsLogkey`) without further security checks.
8. The attacker uses the obtained session cookies to gain full and persistent access to the victim's account, allowing them to read sensitive data, modify records, change permissions, and potentially install malicious plugins.

## Impact

Successful exploitation of CVE-2026-47677 leads to complete account takeover for any 2FA-enabled user within FacturaScripts, including administrative accounts. This results in high confidentiality impact, allowing attackers to access all data visible to the compromised user, such as invoices, customer information, accounting ledgers, attached files, and API keys. The integrity impact is also high, as attackers can create, modify, or delete records, alter user permissions, and potentially upload or install malicious code through admin privileges. Furthermore, the vulnerability enables a targeted denial of service (DoS) by allowing attackers to generate six failed 2FA attempts for a specific user, triggering an account lockout for 10 minutes (`MAX_INCIDENT_COUNT = 6`). This lockout mechanism can be repeatedly exploited, effectively blocking legitimate users from accessing their accounts.

## Recommendation

* Deploy a patch that implements the four fixes outlined in the advisory for CVE-2026-47677, specifically requiring password completion evidence (nonce), CSRF token validation, pre-check of user incidents, and reducing `TwoFactorManager::VERIFICATION_WINDOW` to 1.
* Implement the suggested Sigma rule to detect attempts to access the vulnerable `/login?action=two-factor-validation` endpoint.
* Enhance web server or WAF configurations to implement aggressive rate-limiting for POST requests to the `/login` endpoint, particularly those containing `action=two-factor-validation`.
* Enable comprehensive web server access logging to monitor for repeated POST requests to `/login?action=two-factor-validation` from single source IP addresses.
