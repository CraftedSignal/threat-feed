---
title: CVE-2026-14245 - miniOrange OTP WordPress Plugin Authentication Bypass
slug: 2026-07-miniorange-auth-bypass
description: A critical authentication bypass vulnerability, CVE-2026-14245, exists in the miniOrange OTP Login, Verification and SMS Notifications plugin for WordPress, affecting all versions up to 5.5.1, allowing unauthenticated attackers to obtain a password-reset URL for an arbitrary Administrator account and achieve full account takeover due to a lack of server-side OTP verification and reliance on a publicly exposed `form_nonce`.
date: "2026-07-09T08:22:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - authentication-bypass
  - web
  - cve
vendors:
  - miniOrange
products:
  - miniOrange OTP Login, Verification and SMS Notifications plugin < 5.5.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to obtain a freshly generated password-reset URL for an arbitrary Administrator account
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This makes it possible for unauthenticated attackers to obtain a freshly generated password-reset URL for an arbitrary Administrator account — returned in a 302 `Location` header — and use it to take full control of that account.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: take full control of that account.
    confidence_band: high
cves:
  - id: CVE-2026-14245
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14245
---

The miniOrange OTP Login, Verification and SMS Notifications plugin for WordPress versions up to and including 5.5.1 is vulnerable to an authentication bypass, identified as CVE-2026-14245. This flaw stems from the `um_reset_password_process_hook()` function's failure to perform server-side verification that the One-Time Password (OTP) validation step was completed. The plugin also emits a public `form_nonce` via a JavaScript object on the Ultimate Member password reset page, which attackers can leverage. By combining this nonce with an attacker-controlled `username_b` parameter, an unauthenticated actor can target any WordPress user, including Administrators, and obtain a password-reset URL for their account. This critical vulnerability allows for full account takeover and enables unauthorized administrative control over the affected WordPress instance. Exploitation requires the Ultimate Member Password Reset Form integration to be active and the miniOrange plugin not configured for phone-only reset.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site running the vulnerable miniOrange OTP Login, Verification and SMS Notifications plugin (versions <= 5.5.1) with the Ultimate Member Password Reset Form integration active.
2. The attacker navigates to the Ultimate Member password reset page, where the plugin publicly emits a `form_nonce` via the `moumprvar` JavaScript object. The attacker extracts this nonce value.
3. The attacker crafts a malicious HTTP request (likely a POST request) to the server-side password reset handler (e.g., associated with the `um_reset_password_process_hook()` function).
4. This request includes the extracted `form_nonce` and an attacker-chosen `username_b` parameter, targeting an existing Administrator account on the WordPress site.
5. Due to the vulnerability, the server processes the request without validating whether the OTP verification step was successfully completed for the targeted user.
6. The server responds with an HTTP 302 redirect, providing a freshly generated password-reset URL in the `Location` header for the specified Administrator account.
7. The attacker uses this URL to set a new password for the Administrator account, thereby gaining full administrative control over the WordPress site.

## Impact

The impact of CVE-2026-14245 is severe, as it allows any unauthenticated attacker to gain full administrative control over a vulnerable WordPress site. This can lead to complete compromise of the website, including data exfiltration, website defacement, injection of malicious content, establishment of persistent backdoors, and use of the site for further attacks (e.g., phishing or malware distribution). The vulnerability, with a CVSS v3.1 Base Score of 9.8 (Critical), signifies a high likelihood of successful exploitation with devastating consequences for the affected organization, impacting website integrity, data confidentiality, and availability.

## Recommendation

* Immediately update the miniOrange OTP Login, Verification and SMS Notifications plugin to a patched version beyond 5.5.1 to address CVE-2026-14245.
* Review the configuration of the miniOrange OTP plugin to ensure it is not configured for phone-only reset if other reset methods are intended to be secured.
* Audit WordPress user accounts, especially Administrator accounts, for any unauthorized password changes or suspicious activity that may indicate prior exploitation of CVE-2026-14245.
