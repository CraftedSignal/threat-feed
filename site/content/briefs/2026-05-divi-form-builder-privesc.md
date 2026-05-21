---
title: Divi Form Builder Unauthenticated Privilege Escalation via CVE-2026-5118
slug: 2026-05-divi-form-builder-privesc
description: CVE-2026-5118 is a critical vulnerability in the Divi Form Builder WordPress plugin (versions 5.1.2 and earlier) that allows unauthenticated attackers to create administrator accounts directly through the registration form, leading to full site takeover.
date: "2026-05-21T11:02:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - wordpress
  - privilege escalation
  - cloud
vendors:
  - WordPress
products:
  - Divi Form Builder <= 5.1.2
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://sploitus.com/exploit?id=66FE3CD0-D3F5-5BFE-B5A6-FC6CE964F5E2&utm_source=rss&utm_medium=rss
  - CVE-2026-5118
iocs:
  - type: email
    value: attacker@proton.me
  - type: domain
    value: target.com
ioc_counts:
  domain: 1
  email: 1
rules:
  - title: Detect Divi Form Builder Admin Account Creation
    description: Detects CVE-2026-5118 exploitation — Creation of a new administrator account via the Divi Form Builder registration form.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Suspicious POST Requests to admin-ajax.php with de_fb_ajax_submit_ajax_handler
    description: Detects suspicious POST requests to admin-ajax.php with the de_fb_ajax_submit_ajax_handler action, which could indicate exploitation of vulnerabilities in the Divi Form Builder plugin.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

A critical vulnerability, CVE-2026-5118, has been identified in the Divi Form Builder WordPress plugin, affecting versions 5.1.2 and earlier. This flaw allows unauthenticated attackers to escalate privileges and create administrator accounts via a registration form. The vulnerability stems from insufficient validation of the 'role' parameter in the FormSubmissionHandler.php script during user registration.  A publicly available exploit on Sploitus increases the urgency for patching affected systems. Exploitation leads to full site takeover, data breaches (if WooCommerce is installed), remote code execution via plugin/theme modification, persistent access via backdoors, and privacy violations due to access to all user data.

## Attack Chain

1. **Target Discovery:** The attacker identifies websites using vulnerable versions of the Divi Form Builder plugin by scanning for registration endpoints, crawling homepage links, parsing XML sitemaps, probing the DFB REST API, and analyzing contact pages.
2. **Form Parameter Extraction:** The attacker extracts required form parameters, including `fb_nonce`, `form_key`, `form_type` (register), `divi-form-submit`, and the injectable `role` parameter.
3. **Role Injection:** The attacker crafts a malicious HTTP POST request to `/wp-admin/admin-ajax.php`, setting the `action` parameter to `de_fb_ajax_submit_ajax_handler` and injecting `administrator` into the `role` parameter along with other required fields.
4. **Account Creation:** The vulnerable `create_user()` function in `FormSubmissionHandler.php` creates a new user account with the injected `administrator` role without proper validation.
5. **Privilege Escalation:** The newly created user account is assigned the `administrator` role, granting full control over the WordPress website.
6. **Verification:** The attacker verifies the successful privilege escalation by logging in to `/wp-login.php` with the created account credentials and accessing the `/wp-admin/` dashboard.
7. **Full Site Takeover:** The attacker gains complete control over the WordPress site, including the ability to create/delete any user, install/activate/edit plugins (including PHP), edit theme template files, and modify site settings.

## Impact

Successful exploitation of CVE-2026-5118 allows an unauthenticated attacker to gain full administrative control over a WordPress website. This can lead to complete site defacement, data theft (including customer data from WooCommerce), installation of malicious plugins or themes for further attacks, and persistent access through backdoors. The number of affected sites is potentially large due to the widespread use of the Divi Form Builder plugin.

## Recommendation

*   Immediately update to Divi Form Builder version 5.1.3 or later to patch CVE-2026-5118, as mentioned in the timeline.
*   Deploy the Sigma rule `Detect Divi Form Builder Admin Account Creation` to monitor for successful exploitation attempts.
*   Monitor `wp_users` table for new administrator accounts created through suspicious activity, as suggested in the mitigation section.
*   Apply a WAF rule to block requests with the `role=administrator` parameter in POST requests, as also noted in the mitigation advice.
