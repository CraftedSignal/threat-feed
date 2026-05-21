---
title: CVE-2026-6279 - Avada Builder Plugin Unauthenticated RCE via PHP Function Injection
slug: 2026-05-avada-builder-rce
description: The Avada Builder (fusion-builder) plugin for WordPress is vulnerable to unauthenticated remote code execution (RCE) due to PHP function injection, allowing attackers to execute arbitrary code on affected sites.
date: "2026-05-21T05:16:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - rce
  - php
  - function-injection
  - cve-2026-6279
vendors:
  - WordPress
products:
  - Avada Builder (fusion-builder) plugin <= 3.15.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-6279
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6279
rules:
  - title: Detect Avada Builder PHP Function Injection Attempt
    description: Detects CVE-2026-6279 exploitation — attempts to inject PHP functions via the fusion_get_widget_markup endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
  - title: Detect Avada Builder fusion_get_widget_markup Endpoint Access
    description: Detects access to the fusion_get_widget_markup AJAX endpoint, potentially indicating CVE-2026-6279 exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The Avada Builder (fusion-builder) plugin for WordPress, specifically versions up to and including 3.15.2, contains an unauthenticated remote code execution vulnerability, tracked as CVE-2026-6279. The vulnerability stems from a lack of proper validation when handling the `wp_conditional_tags` case within the `Fusion_Builder_Conditional_Render_Helper::get_value()` function. This allows attacker-controlled values from a base64-decoded JSON blob to be passed directly to `call_user_func()`, resulting in PHP function injection. The `fusion_get_widget_markup` AJAX endpoint, accessible to unauthenticated users via `wp_ajax_nopriv_fusion_get_widget_markup`, can be exploited. Although a nonce (`fusion_load_nonce`) is present, it is generated for user ID 0 and deterministically exposed in the JavaScript output of public-facing pages containing a Post Cards (`[fusion_post_cards]`) or Table of Contents (`[fusion_table_of_contents]`) element, bypassing the intended authentication mechanism.

## Attack Chain

1.  The attacker identifies a WordPress site running a vulnerable version of the Avada Builder plugin (<= 3.15.2).
2.  The attacker visits a public-facing page containing either a Post Cards (`[fusion_post_cards]`) or Table of Contents (`[fusion_table_of_contents]`) element.
3.  The attacker extracts the `fusion_load_nonce` value from the page's JavaScript source code.
4.  The attacker crafts a malicious AJAX request to the `fusion_get_widget_markup` endpoint, including the extracted `fusion_load_nonce` value.
5.  The attacker injects a PHP function call within the base64-decoded JSON blob passed to `Fusion_Builder_Conditional_Render_Helper::get_value()` via the `wp_conditional_tags` case.
6.  The `call_user_func()` function executes the attacker-controlled PHP function.
7.  The attacker executes arbitrary code on the WordPress server.
8.  The attacker achieves full control of the WordPress site.

## Impact

Successful exploitation of CVE-2026-6279 allows unauthenticated attackers to execute arbitrary code on vulnerable WordPress sites. This can lead to complete compromise of the affected website, including data theft, defacement, malware injection, and denial of service. Given the popularity of the Avada Builder plugin, a large number of WordPress sites are potentially at risk.

## Recommendation

*   Upgrade the Avada Builder plugin to a version greater than 3.15.2 to patch CVE-2026-6279.
*   Deploy the Sigma rule `Detect Avada Builder PHP Function Injection Attempt` to identify exploitation attempts against the `fusion_get_widget_markup` endpoint.
*   Monitor web server logs for POST requests to `/wp-admin/admin-ajax.php` with `action=fusion_get_widget_markup` containing suspicious base64 encoded data, as detected by `Detect Avada Builder fusion_get_widget_markup Endpoint Access`.
