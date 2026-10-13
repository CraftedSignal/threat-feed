---
title: 'CVE-2026-12415: WordPress Invoice Generator Plugin Unauthenticated Privilege Escalation'
slug: 2026-06-wordpress-invoice-generator-privesc
description: An authentication bypass vulnerability (CVE-2026-12415) in the Invoice Generator plugin for WordPress (versions up to and including 1.0.0) allows unauthenticated attackers to perform privilege escalation by modifying the email address of any user, including administrators, and subsequently gaining full account control via a password reset.
date: "2026-06-27T05:19:41Z"
lastmod: "2026-10-13T06:41:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:pravel:invoice_generator_plugin_1_0_0:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-XXCONI-CVE-2026-12415-OR-CVE-2026-12416.PY&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - plugin
  - privilege-escalation
  - webserver
  - cve
vendors:
  - Pravel
products:
  - Invoice Generator plugin <= 1.0.0 (<= 1.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: unauthenticated attackers to change the email address of any user, including administrators
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: change the email address of any user, including administrators, and then trigger WordPress's password reset flow to gain access to the targeted account.
    confidence_band: high
cves:
  - id: CVE-2026-12415
    cvss: 9.8
    epss: 0.00804
  - id: CVE-2026-12416
    cvss: 9.8
    epss: 0.00673
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12415
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-XXCONI-CVE-2026-12415-OR-CVE-2026-12416.PY&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-12415 Exploitation - Invoice Generator Plugin PrivEsc
    description: Detects exploitation attempts against CVE-2026-12415, an unauthenticated privilege escalation vulnerability in the WordPress Invoice Generator plugin, by monitoring for POST requests to the vulnerable AJAX action.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1098
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-10-13T06:41:02Z"
    level: L2
    summary: poc_available; added CVE-2026-12416; invoice generator plugin <= 1.0.0 version <= 1.0.0
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-XXCONI-CVE-2026-12415-OR-CVE-2026-12416.PY&utm_source=rss&utm_medium=rss
---

A critical privilege escalation vulnerability, tracked as CVE-2026-12415, has been identified in the Invoice Generator plugin for WordPress. This flaw impacts all plugin versions up to and including 1.0.0. The vulnerability stems from a missing capability check on the `pravel_invoice_edit_account()` AJAX action, which is exposed to unauthenticated users via `wp_ajax_nopriv_pravel_invoice_edit_account`. This specific handler accepts `user_id` and `user_email` parameters from POST data without verifying the requester's authentication status, ownership, or a nonce. This critical oversight allows unauthenticated attackers to arbitrarily change the email address of any user on the WordPress site, including administrative accounts. By exploiting this, attackers can trigger WordPress's password reset mechanism to gain full control over the compromised account.

## Attack Chain

1.  **Discovery:** An unauthenticated attacker identifies a WordPress instance running the vulnerable "Invoice Generator" plugin (versions up to and including 1.0.0).
2.  **Target Identification:** The attacker identifies the `user_id` (e.g., typically `1` for the main administrator) and a legitimate administrator username on the target WordPress site.
3.  **Email Modification Request:** The attacker sends an unauthenticated HTTP POST request to `/wp-admin/admin-ajax.php` with the `action=pravel_invoice_edit_account` parameter in the query string and includes the target `user_id` and a new, attacker-controlled `user_email` in the POST body or query parameters.
4.  **Vulnerability Trigger:** The vulnerable plugin's `pravel_invoice_edit_account()` function, lacking proper authentication and authorization checks, processes the request and updates the target administrator's email address to the attacker-provided email.
5.  **Password Reset Initiation:** The attacker navigates to the WordPress login page and initiates a password reset flow for the targeted administrator account using the administrator's username.
6.  **Password Reset Delivery:** WordPress sends the password reset link to the newly assigned, attacker-controlled email address.
7.  **Account Takeover:** The attacker accesses the attacker-controlled email inbox, clicks the password reset link, sets a new password, and successfully logs into the WordPress site as the administrator.
8.  **Impact:** The attacker gains full administrative control over the WordPress site, enabling various malicious activities.

## Impact

Successful exploitation of CVE-2026-12415 leads to complete administrative control over the affected WordPress site. This allows attackers to perform a wide range of damaging actions, including website defacement, injection of malicious code (e.g., for drive-by downloads or phishing campaigns), exfiltration of sensitive data from the site's database, or using the compromised site as a platform for further attacks. Organizations running the vulnerable plugin face a high risk of website takeover, reputational damage, and potential compliance breaches if sensitive customer data is stored on the platform.

## Recommendation

*   Prioritize patching the "Invoice Generator" WordPress plugin to a version greater than 1.0.0 immediately.
*   Deploy the provided Sigma rule to your SIEM to detect exploitation attempts against CVE-2026-12415.
*   Ensure web server access logs are collected for the `webserver` category, as this log source is crucial for detecting exploitation.
