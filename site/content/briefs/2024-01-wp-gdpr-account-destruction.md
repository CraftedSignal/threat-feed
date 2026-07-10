---
title: WP DSGVO Tools (GDPR) Plugin Vulnerable to Account Destruction (CVE-2026-4283)
slug: 2024-01-wp-gdpr-account-destruction
description: The WP DSGVO Tools (GDPR) WordPress plugin before version 3.1.39 is vulnerable to unauthenticated account destruction via the `super-unsubscribe` AJAX action, allowing attackers to irreversibly anonymize non-administrator user accounts.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - gdpr
  - account-destruction
  - cve-2026-4283
vendors:
  - WP DSGVO Tools
products:
  - WP DSGVO Tools (GDPR) plugin
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4283
iocs:
  - type: email
    value: victim's email address
ioc_counts:
  email: 1
rules:
  - title: Detect Unauthenticated Account Destruction Attempt via WP GDPR Plugin
    description: Detects attempts to exploit CVE-2026-4283 by monitoring for POST requests to /wp-admin/admin-ajax.php with the super-unsubscribe action and process_now parameter set to 1.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Detect super-unsubscribe AJAX call with missing referer
    description: Detects attempts to exploit the super-unsubscribe action without proper referer, potentially indicating malicious intent
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The WP DSGVO Tools (GDPR) plugin for WordPress, in versions up to and including 3.1.38, contains a critical vulnerability (CVE-2026-4283) that allows unauthenticated attackers to destroy user accounts. The vulnerability resides in the `super-unsubscribe` AJAX action, which is intended to handle account anonymization requests. However, by providing the `process_now=1` parameter along with a target user's email address, an attacker can bypass the email confirmation flow and immediately trigger the irreversible account anonymization process. The nonce value required for this AJAX request is exposed on any page containing the `[unsubscribe_form]` shortcode, making exploitation straightforward. This issue poses a significant risk to WordPress sites utilizing the affected plugin, potentially leading to widespread data loss and disruption of services.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using a vulnerable version of the WP DSGVO Tools (GDPR) plugin (<= 3.1.38).
2. The attacker navigates to a page on the target site that includes the `[unsubscribe_form]` shortcode to obtain the required nonce.
3. The attacker crafts a malicious AJAX request targeting the `super-unsubscribe` action endpoint (e.g., `/wp-admin/admin-ajax.php`).
4. The request includes the `action` parameter set to `super-unsubscribe`, the `process_now` parameter set to `1`, the victim's email address, and the extracted nonce value.
5. The WordPress server processes the request without requiring email confirmation due to the `process_now=1` parameter.
6. The targeted user account undergoes irreversible anonymization: password randomized, username/email overwritten, roles stripped, comments anonymized, sensitive usermeta wiped.
7. The victim loses access to their account, and their data is effectively destroyed.

## Impact

Successful exploitation of CVE-2026-4283 allows an unauthenticated attacker to permanently destroy non-administrator user accounts on affected WordPress sites. This leads to a loss of user data, disruption of services for affected users, and potential reputational damage for the website owner. The vulnerability affects all sites running the WP DSGVO Tools (GDPR) plugin versions 3.1.38 and earlier. A successful attack renders the targeted user account unusable, requiring manual intervention to recover (if possible).

## Recommendation

*   Immediately update the WP DSGVO Tools (GDPR) plugin to version 3.1.39 or later to patch CVE-2026-4283.
*   Deploy the Sigma rule "Detect Unauthenticated Account Destruction Attempt via WP GDPR Plugin" to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for POST requests to `/wp-admin/admin-ajax.php` with `action=super-unsubscribe` and `process_now=1`, as detected by the provided Sigma rule.
