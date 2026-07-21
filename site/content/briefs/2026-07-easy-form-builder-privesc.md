---
title: WordPress Easy Form Builder Plugin Vulnerable to Unauthenticated Administrator Privilege Escalation (CVE-2026-13439)
slug: 2026-07-easy-form-builder-privesc
description: An unauthenticated privilege escalation vulnerability exists in the Easy Form Builder by WhiteStudio plugin for WordPress, affecting versions up to and including 4.0.11, allowing attackers to exploit a flaw in the password recovery process by using a publicly visible session identifier ('sid') as a reset token, combined with a publicly accessible nonce refresh endpoint, to set an arbitrary new password for any WordPress user, including administrators, to gain full control.
date: "2026-07-21T06:19:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - privilege-escalation
  - web-vulnerability
vendors:
  - WhiteStudio
  - WordPress
products:
  - Easy Form Builder by WhiteStudio plugin for WordPress <= 4.0.11
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This makes it possible for unauthenticated attackers to reset the password of any WordPress user — including administrators — by scraping the public sid from a published login form page, submitting a recovery request for any known user email via Emsfb/v1/forms/message/add, and then calling Emsfb/v1/forms/recovery/efb_set_password with the known sid to set an arbitrary new password and gain full administrator access.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This makes it possible for unauthenticated attackers to reset the password of any WordPress user — including administrators — by scraping the public sid from a published login form page, submitting a recovery request for any known user email via Emsfb/v1/forms/message/add, and then calling Emsfb/v1/forms/recovery/efb_set_password with the known sid to set an arbitrary new password and gain full administrator access.
    confidence_band: high
cves:
  - id: CVE-2026-13439
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13439
rules:
  - title: Detects CVE-2026-13439 Exploitation Attempts via Password Reset Endpoint
    description: Detects attempts to exploit CVE-2026-13439, an unauthenticated privilege escalation vulnerability in the WordPress Easy Form Builder plugin, by monitoring for POST requests to the vulnerable password reset endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1078.003
      - T1098.006
    data_sources:
      - webserver
rules_count: 1
---

The Easy Form Builder by WhiteStudio plugin for WordPress is affected by a critical unauthenticated privilege escalation vulnerability, tracked as CVE-2026-13439, in versions up to and including 4.0.11. This flaw stems from a insecure password recovery mechanism that relies on a publicly visible session identifier ('sid') acting as a password reset token. Attackers can leverage this by first scraping the 'sid' from a published login form page. They then submit a password recovery request for any known user email, including administrative accounts, via the `Emsfb/v1/forms/message/add` endpoint. A publicly accessible nonce refresh endpoint, `Emsfb/v1/nonce/refresh`, further aids exploitation by providing valid WordPress REST nonces to unauthenticated users. Finally, by calling `Emsfb/v1/forms/recovery/efb_set_password` with the harvested 'sid' and a valid nonce, an attacker can set an arbitrary new password for the target account, ultimately gaining full administrator access to the WordPress site. This vulnerability poses a severe risk, enabling complete site compromise without requiring any prior authentication.

## Attack Chain

1. **Information Gathering**: An unauthenticated attacker accesses a WordPress site using the Easy Form Builder plugin and scrapes the publicly visible session identifier ('sid') from a published login form page.
2. **Password Recovery Request**: The attacker crafts and sends a request to the `Emsfb/v1/forms/message/add` endpoint, initiating a password recovery process for a known WordPress user's email address, targeting an administrator account if possible.
3. **Nonce Acquisition**: The attacker accesses the publicly accessible `Emsfb/v1/nonce/refresh` endpoint to obtain a valid WordPress REST nonce without needing authentication.
4. **Password Reset Execution**: With the scraped 'sid' and the acquired valid nonce, the attacker sends a request to the `Emsfb/v1/forms/recovery/efb_set_password` endpoint, providing a new arbitrary password.
5. **Privilege Escalation**: The plugin's flawed logic processes the request, resetting the target user's password to the attacker-defined value.
6. **Administrative Access**: The attacker uses the newly set password to log in as the compromised user, effectively gaining full administrator access to the WordPress site.

## Impact

Successful exploitation of CVE-2026-13439 grants unauthenticated attackers full administrator control over the affected WordPress site. This allows them to execute arbitrary code, manipulate website content, deploy malicious plugins, steal sensitive data, deface the website, or use it as a platform for further attacks. The high CVSS v3.1 base score of 9.8 reflects the critical nature of this vulnerability, indicating ease of exploitation and severe consequences without any user interaction or authentication required. Any organization running the vulnerable plugin faces complete compromise of their WordPress installation.

## Recommendation

* Immediately patch the Easy Form Builder by WhiteStudio plugin to a version beyond 4.0.11 to remediate CVE-2026-13439.
* Deploy the Sigma rule "Detects CVE-2026-13439 Exploitation Attempts via Password Reset Endpoint" to your SIEM for early detection of exploitation attempts.
* Enable comprehensive web server logging for HTTP POST requests to the `Emsfb/v1/forms/recovery/efb_set_password`, `Emsfb/v1/forms/message/add`, and `Emsfb/v1/nonce/refresh` endpoints.
* Regularly review web server access logs for suspicious activity, particularly involving the IOCs `Emsfb/v1/forms/recovery/efb_set_password`, `Emsfb/v1/forms/message/add`, and `Emsfb/v1/nonce/refresh`.
