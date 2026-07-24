---
title: Pheditor Authentication Bypass via Unverified Current Password in Forced Password Change
slug: 2026-07-pheditor-auth-bypass
description: A critical authentication bypass vulnerability in Pheditor versions prior to 2.0.8 allows an unauthenticated attacker to gain full administrative access by exploiting a flaw in the forced password-change flow, enabling them to set an arbitrary new admin password and obtain an authenticated session without knowing the current one.
date: "2026-07-24T21:56:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - web-application
  - ghsa
  - network
vendors:
  - Pheditor
products:
  - pheditor (< 2.0.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authentication bypass vulnerability in Pheditor (versions prior to 2.0.8) allows an unauthenticated attacker to gain full administrative access.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An unauthenticated attacker can set an arbitrary new admin password and obtain a fully authenticated session
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An unauthenticated attacker can set an arbitrary new admin password and obtain a fully authenticated session, without knowing the current password.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-f25v-x6vr-962g
---

A critical authentication bypass vulnerability (GHSA-f25v-x6vr-962g) exists in Pheditor, a single-admin PHP file editor, affecting all versions prior to 2.0.8. This flaw allows an unauthenticated attacker to completely circumvent the authentication mechanism and gain full administrative control over any Pheditor instance where the default 'admin' password has not yet been changed. The vulnerability specifically lies within the forced password-change flow, which is triggered when Pheditor detects that the stored admin password is still its default value. Attackers can exploit this by sending an HTTP POST request to `pheditor.php` that includes an arbitrary non-empty value for the `pheditor_password` parameter, along with a desired new password in `pheditor_new_password` and `pheditor_confirm_password`. The system fails to verify the submitted `pheditor_password` against the actual current password, enabling the attacker to force a password change and subsequently obtain an authenticated session. This significantly compromises the security of affected Pheditor installations, as it grants unauthorized individuals the ability to execute arbitrary PHP code and manipulate the server's file system, leading to potential data compromise or system takeover.

## Attack Chain

1. An unauthenticated attacker identifies a Pheditor instance running a vulnerable version (prior to 2.0.8) via direct access to `pheditor.php`.
2. The attacker confirms the Pheditor instance is configured with the default 'admin' password, which triggers the forced password-change flow upon attempting to log in.
3. The attacker crafts an HTTP POST request targeting the `pheditor.php` endpoint.
4. The POST request includes a `pheditor_password` parameter with any non-empty string value (e.g., `pheditor_password=anything`).
5. The request also includes `pheditor_new_password` and `pheditor_confirm_password` parameters, specifying the attacker's desired new admin password (e.g., `pheditor_new_password=attacker123&pheditor_confirm_password=attacker123`).
6. The vulnerable `pheditor.php` script at line 163 identifies that the stored `PASSWORD` constant is still the default 'admin' hash.
7. Due to the vulnerability, the script proceeds to the password change logic without verifying if the attacker's supplied `pheditor_password` value actually matches the current password.
8. The system updates the 'admin' account's password to the value provided by the attacker, granting the attacker a fully authenticated session and complete administrative control.

## Impact

Successful exploitation of this vulnerability results in a complete authentication bypass and full administrative compromise of the Pheditor instance. An unauthenticated attacker can arbitrarily change the administrator password and gain an authenticated session, granting them unrestricted access to edit, create, or delete files on the web server. Since Pheditor is a PHP file editor, this access directly translates to arbitrary code execution capabilities, allowing the attacker to inject malicious scripts, deface websites, exfiltrate data, or establish persistent backdoors on the compromised server. The impact extends to any data and systems accessible by the web server process, potentially leading to severe data breaches, system integrity loss, and further network compromise. The vulnerability is especially dangerous because it negates any perceived security from the presence of a login form, as the attacker does not need to know the default password.

## Recommendation

* Immediately patch Pheditor instances to version 2.0.8 or later to remediate CVE-2026-XXXX (GHSA-f25v-x6vr-962g).
* Monitor web server access logs for HTTP POST requests to the `/pheditor.php` endpoint that contain parameters related to password changes (`pheditor_new_password`, `pheditor_confirm_password`) from unusual or unauthenticated sources.
