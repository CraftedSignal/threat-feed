---
title: Grav Two-Factor Authentication Bypass Vulnerability (CVE-2026-62232)
slug: 2026-07-grav-2fa-bypass
description: A high-severity two-factor authentication bypass vulnerability (CVE-2026-62232) in Grav CMS before version 2.0.4 allows an attacker with a victim's password to overwrite their 2FA secret via the `regenerate2FASecret` task, enabling unauthorized access by generating a valid TOTP code and reducing multi-factor authentication to password-only protection.
date: "2026-07-17T02:36:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - grav
  - 2fa-bypass
  - vulnerability
  - web-application
vendors:
  - Grav
products:
  - Grav (< 2.0.4)
  - Grav login plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers who know the victim's password can call this task...and complete authentication
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: overwrite the 2FA secret with an attacker-chosen value, compute a valid TOTP code, and complete authentication while reducing 2FA to password-only protection.
    confidence_band: high
cves:
  - id: CVE-2026-62232
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62232
  - https://github.com/getgrav/grav/security/advisories/GHSA-7mgc-c7pq-3rr3
  - https://www.vulncheck.com/advisories/grav-2fa-bypass-via-secret-regeneration
rules:
  - title: Detects CVE-2026-62232 Exploitation - Grav 2FA Secret Regeneration Bypass
    description: Detects attempts to exploit CVE-2026-62232 where an attacker attempts to regenerate a user's 2FA secret on Grav CMS instances before 2.0.4. This is typically done via an unauthenticated POST request to the regenerate2FASecret task, bypassing authorization and CSRF protection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1078.004
      - T1098.006
    data_sources:
      - webserver
rules_count: 1
---

A significant vulnerability, identified as CVE-2026-62232, exists in Grav CMS versions prior to 2.0.4, specifically within its login plugin. This flaw allows for a complete bypass of two-factor authentication (2FA). Attackers who have already obtained a victim's password can exploit a critical authorization weakness in the `regenerate2FASecret` task. During the pending Time-based One-Time Password (TOTP) challenge window, this task only verifies user existence, not proper authorization, and notably lacks Cross-Site Request Forgery (CSRF) protection. By calling this task, an attacker can overwrite the victim's legitimate 2FA secret with an attacker-chosen value. This allows the attacker to compute a valid TOTP code and complete the authentication process, effectively rendering the 2FA mechanism useless and granting unauthorized access to the Grav administration panel. This vulnerability poses a severe risk to Grav installations that rely on 2FA for enhanced security.

## Attack Chain

1. Attacker obtains a valid user's password for a Grav CMS instance (pre-requisite).
2. Attacker initiates a login attempt to the Grav administration panel, submitting the valid password for the target user.
3. During the pending TOTP challenge window (after password submission but before 2FA code entry), the attacker sends an HTTP POST request to the `/admin/login/task:regenerate2FASecret` endpoint.
4. The Grav application processes this request, verifying the existence of the user but failing to perform proper authorization checks for the secret regeneration action.
5. Due to the lack of a CSRF nonce, the application accepts the attacker's request and overwrites the target user's legitimate 2FA secret with a new secret value provided or chosen by the attacker.
6. The attacker then calculates a valid TOTP code using the newly established, attacker-controlled 2FA secret.
7. The attacker submits the calculated TOTP code to complete the authentication process, bypassing the user's original 2FA setup.
8. Attacker gains unauthorized, authenticated access to the Grav administration panel, effectively reducing security to password-only protection.

## Impact

Successful exploitation of CVE-2026-62232 grants unauthorized access to the Grav CMS administration panel for any user whose password has been compromised. This directly compromises the integrity and confidentiality of the affected Grav installation, as attackers can then manipulate content, settings, and potentially deploy malicious code. The vulnerability effectively nullifies the security benefits of two-factor authentication, making user accounts as vulnerable as if only a password was required. The NVD assigns this vulnerability a CVSS 3.1 Base Score of 7.4 (High), indicating a significant security risk for organizations using vulnerable Grav instances.

## Recommendation

* Patch Grav CMS to version 2.0.4 or higher immediately to address CVE-2026-62232.
* Deploy the Sigma rule `Grav 2FA Secret Regeneration Bypass` to your SIEM system to detect exploitation attempts against CVE-2026-62232.
* Monitor web server access logs for suspicious HTTP POST requests to the `/admin/login/task:regenerate2FASecret` URI, especially if not preceded by a legitimate user-initiated 2FA regeneration flow.
