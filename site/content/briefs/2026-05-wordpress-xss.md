---
title: WordPress Auto Affiliate Links Plugin Stored XSS Vulnerability (CVE-2026-7330)
slug: 2026-05-wordpress-xss
description: The Auto Affiliate Links plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) in versions up to 6.8.8 due to insufficient input sanitization and output escaping, allowing unauthenticated attackers to inject arbitrary web scripts into the admin statistics page.
date: "2026-05-08T09:16:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - xss
  - plugin
vendors:
  - WordPress
products:
  - Auto Affiliate Links plugin <= 6.8.8
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7330
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7330
rules:
  - title: Detect WordPress Auto Affiliate Links Plugin XSS Attempt
    description: Detects CVE-2026-7330 exploitation — Monitors POST requests with suspicious characters in the 'url' parameter indicative of a XSS attempt on Auto Affiliate Links plugin.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect WordPress Auto Affiliate Links Plugin XSS Persistence via Database
    description: Detects CVE-2026-7330 exploitation — Detects stored XSS payloads in WordPress options table related to Auto Affiliate Links plugin
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The Auto Affiliate Links plugin, a WordPress plugin, is susceptible to a stored Cross-Site Scripting (XSS) vulnerability affecting versions up to and including 6.8.8. The vulnerability stems from a lack of proper input sanitization within the `aal_url_stats_save_action()` function when handling the 'url' POST parameter. Additionally, there is a complete absence of output escaping in the `aal_display_clicks()` function, where user-supplied input is directly echoed into an anchor element's `href` attribute and inner text without applying `esc_url()`, `esc_attr()`, or `esc_html()`. Attackers can exploit this vulnerability without authentication by injecting malicious web scripts into the admin statistics page using a publicly exposed nonce and an unauthenticated AJAX endpoint registered through the `wp_ajax_nopriv_` hook. Successful exploitation results in the execution of arbitrary web scripts within an administrator's browser upon visiting the affected page.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP POST request to the WordPress site's AJAX endpoint (`wp-admin/admin-ajax.php`).
2. The POST request includes the `action` parameter set to `aal_url_stats_save_action` and a `url` parameter containing the XSS payload.
3. WordPress processes the AJAX request, invoking the `aal_url_stats_save_action()` function within the Auto Affiliate Links plugin.
4. The `aal_url_stats_save_action()` function fails to properly sanitize the `url` parameter, allowing the XSS payload to be stored in the WordPress database.
5. An administrator visits the admin statistics page, which calls the `aal_display_clicks()` function to display the stored URLs.
6. The `aal_display_clicks()` function retrieves the unsanitized URL containing the XSS payload from the database.
7. The XSS payload is echoed directly into the `href` attribute and inner text of an anchor element without proper escaping via `esc_url()`, `esc_attr()`, or `esc_html()`.
8. The administrator's browser executes the injected XSS payload, potentially leading to account compromise or further malicious actions.

## Impact

Successful exploitation of this stored XSS vulnerability can allow an unauthenticated attacker to execute arbitrary JavaScript code in the context of an administrator's browser. This could lead to a variety of malicious activities, including account takeover, defacement of the WordPress site, or redirection of users to malicious websites. Given the lack of authentication required for the initial injection, the vulnerability poses a significant risk to websites using the affected plugin.

## Recommendation

*   Upgrade the Auto Affiliate Links plugin to the latest version, which includes a fix for CVE-2026-7330.
*   Deploy the Sigma rule "Detect WordPress Auto Affiliate Links Plugin XSS Attempt" to identify potential exploitation attempts by monitoring POST requests with suspicious characters in the `url` parameter.
*   Implement proper input sanitization and output escaping techniques in all WordPress plugins to prevent similar XSS vulnerabilities.
