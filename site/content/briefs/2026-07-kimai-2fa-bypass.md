---
title: Kimai REST API Two-Factor Authentication Bypass Vulnerability
slug: 2026-07-kimai-2fa-bypass
description: A critical vulnerability, CVE-2026-52827, in Kimai versions prior to 2.59.0 allows an attacker who has compromised a user's password to bypass Two-Factor Authentication (TOTP) for the REST API by intercepting and replaying the `KIMAI_SESSION` cookie obtained after password verification but before TOTP completion, granting full authenticated API access.
date: "2026-07-14T00:35:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kimai
  - api
  - 2fa-bypass
  - vulnerability
  - web-application
vendors:
  - Kimai
products:
  - Kimai (< 2.59.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: If an attacker obtains a user's password (phishing, credential stuffing, reuse, breach)
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1621
    technique_name: Multi-Factor Authentication Request Generation
    evidence: Two-factor authentication (TOTP) can be fully bypassed for the REST API.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-v8hx-4vx8-wc96
  - https://www.kimai.org/en/security/ghsa-v8hx-4vx8-wc96
---

A critical authentication bypass vulnerability, identified as CVE-2026-52827, affects Kimai versions prior to 2.59.0, allowing attackers to circumvent Two-Factor Authentication (TOTP) for the REST API. This flaw enables an attacker who has compromised a user's password to obtain a `KIMAI_SESSION` cookie during the initial login phase, even before the TOTP step is completed. By replaying this cookie against any `/api/*` endpoint, the attacker gains full authenticated API access as the legitimate user without ever needing to provide the second authentication factor. This vulnerability effectively nullifies 2FA protection for Kimai's API, exposing affected instances to unauthorized data access and manipulation.

## Attack Chain

1. An attacker obtains a user's password for a Kimai instance through various means (e.g., phishing, credential stuffing, or password reuse).
2. The attacker initiates a login attempt to the Kimai web UI (`/en/auth/login`) using the compromised credentials.
3. Kimai's authentication process validates the provided password and, before prompting for the Two-Factor Authentication (TOTP) code, issues a `KIMAI_SESSION` cookie.
4. The attacker intercepts this `KIMAI_SESSION` cookie from the HTTP response, prior to the TOTP verification step.
5. The attacker then crafts subsequent HTTP requests to any `/api/*` endpoint, including the intercepted `KIMAI_SESSION` cookie in the request headers.
6. Due to a logical flaw in Kimai's API firewall and `APIVoter` (specifically using `IS_AUTHENTICATED` instead of `IS_AUTHENTICATED_REMEMBERED` and not properly checking `TwoFactorTokenInterface` status), the API treats the session as fully authenticated.
7. This grants the attacker complete, unauthorized access to the Kimai REST API, allowing them to perform any actions permitted to the compromised user, effectively bypassing the intended 2FA protection.
8. The attacker can now exfiltrate sensitive data, manipulate time entries, or perform other malicious actions via the API.

## Impact

This vulnerability completely neutralizes the protection offered by Two-Factor Authentication for Kimai's REST API. If an attacker successfully compromises a user's password, they gain full authenticated API access, irrespective of whether 2FA is enabled for that account. This can lead to unauthorized access to sensitive user data, manipulation of time tracking entries, and other critical business functions managed via the API. The exploit requires only the compromised password and the `KIMAI_SESSION` cookie, making it a straightforward attack vector.

## Recommendation

* Patch Kimai installations immediately to version 2.59.0 or later to address CVE-2026-52827, which includes updated API firewall logic.
* Verify that the `config/packages/security.yaml` file in your Kimai instance correctly utilizes `IS_AUTHENTICATED_REMEMBERED` for API paths and that the `APIVoter` checks for `TwoFactorTokenInterface` and `IS_AUTHENTICATED_2FA_IN_PROGRESS` status, as outlined in the solution section of the advisory.
