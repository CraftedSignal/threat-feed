---
title: Unauthenticated SQL Injection in WP Multi Store Locator Pro
slug: 2026-09-wp-multi-store-locator-sqli
description: The WP Multi Store Locator Pro plugin for WordPress is vulnerable to unauthenticated SQL injection via the 'store_locatore_search_radius' parameter due to inadequate input sanitization and a lack of prepared statements.
date: "2026-09-18T10:05:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp_multi_store_locator_pro_project:wp_multi_store_locator_pro:*:*:*:*:*:wordpress:*:*
products:
  - WP Multi Store Locator Pro (<= 4.5.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The AJAX handler is registered on wp_ajax_nopriv_make_search_request with no nonce or capability check, making it fully accessible without authentication.
    confidence_band: high
cves:
  - id: CVE-2026-15275
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15275
rules:
  - title: Detects CVE-2026-15275 Exploitation - Unauthenticated SQLi in WP Multi Store Locator
    description: Detects potential exploitation of CVE-2026-15275 by identifying POST requests to the WordPress AJAX endpoint with suspicious SQL characters in the store_locatore_search_radius parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy WAF rules to block requests matching the detection logic for CVE-2026-15275
      owner: SOC
      due: 24h
      evidence: NVD vulnerability disclosure regarding unauthenticated SQL injection
  mitigation_plan:
    - priority: immediate
      action: Upgrade WP Multi Store Locator Pro to a version newer than 4.5.1
      owner: IT Operations
      addresses: CVE-2026-15275
      evidence: Source states all versions up to 4.5.1 are vulnerable
---

The WP Multi Store Locator Pro plugin for WordPress (versions up to and including 4.5.1) contains a critical SQL injection vulnerability identified as CVE-2026-15275. The flaw exists within the 'store_locatore_search_radius' parameter handled by the 'wp_ajax_nopriv_make_search_request' AJAX handler. Because the handler is registered without nonce verification or user capability checks, the endpoint is accessible to unauthenticated remote attackers. 

The vulnerability arises because the plugin fails to properly prepare SQL queries or sanitize input before including it in database operations. Specifically, the injection occurs in a numeric, unquoted SQL context, which effectively bypasses WordPress's standard 'wp_magic_quotes()' addslashes-based protection. If exploited, an attacker can append malicious SQL commands to legitimate queries to exfiltrate sensitive data from the WordPress database. This represents a significant risk for organizations running this plugin on internet-facing WordPress instances.

## Impact

Successful exploitation allows an unauthenticated remote attacker to perform unauthorized SQL queries against the underlying database. This could result in the exfiltration of sensitive configuration data, user credentials, or administrative information contained within the WordPress database. The scope of impact is potentially any site utilizing versions 4.5.1 or older of the WP Multi Store Locator Pro plugin.

## Recommendation

* Update the WP Multi Store Locator Pro plugin to the latest available version beyond 4.5.1 to remediate CVE-2026-15275.
* Monitor web server access logs for anomalous requests directed at the WordPress AJAX endpoint related to the 'make_search_request' action.
* Review database query logs or error logs for SQL syntax errors originating from non-authenticated users.
* Disable the plugin immediately if an update is not currently available and the site is public-facing.
