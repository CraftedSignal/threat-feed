---
title: SQL Injection Vulnerability in WCFM Marketplace Plugin
slug: 2026-09-wcfm-sql-injection
description: The WCFM Marketplace plugin for WordPress is vulnerable to unauthenticated SQL injection via the wcfmmp_user_location_lng parameter, allowing attackers to extract sensitive database information.
date: "2026-09-18T10:05:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wcfm:marketplace_multivendor_marketplace_for_woocommerce:*:*:*:*:*:*:*:*
vendors:
  - WCFM
products:
  - WCFM Marketplace – Multivendor Marketplace for WooCommerce (<= 3.8.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The WCFM Marketplace – Multivendor Marketplace for WooCommerce plugin for WordPress is vulnerable to generic SQL Injection via the 'wcfmmp_user_location_lng' parameter.
    confidence_band: high
cves:
  - id: CVE-2026-18442
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18442
rules:
  - title: Detects CVE-2026-18442 Exploitation - Unauthenticated SQL Injection in WCFM Marketplace
    description: Detects HTTP GET or POST requests targeting the wcfmmp_user_location_lng parameter with SQL injection payloads.
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
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade WCFM Marketplace - Multivendor Marketplace for WooCommerce to the patched version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-18442
  mitigation_plan:
    - priority: immediate
      action: Patch plugin to version > 3.8.2
      owner: IT Operations
      addresses: CVE-2026-18442
      evidence: Vulnerability exists up to and including 3.8.2
---

The WCFM Marketplace - Multivendor Marketplace for WooCommerce plugin for WordPress is affected by a SQL injection vulnerability (CVE-2026-18442) in versions up to and including 3.8.2. The flaw exists due to improper input sanitization and insufficient preparation of SQL queries involving the 'wcfmmp_user_location_lng' parameter. Because the plugin does not correctly escape user-supplied data before passing it to the database, unauthenticated attackers can craft malicious inputs to manipulate backend queries. Successful exploitation allows for the execution of arbitrary SQL commands, which may lead to unauthorized access to sensitive site information, including user credentials, configuration details, and customer transaction records. Defenders should prioritize updating to the latest secure version of the plugin and monitoring web access logs for anomalous character sequences in parameters associated with location data.

## Impact

The vulnerability poses a high risk to WordPress environments running the WCFM Marketplace plugin. If exploited, an unauthenticated attacker can perform unauthorized database queries, potentially leading to the full compromise of the database contents. This impacts the confidentiality and integrity of all store data, including personal identifiable information (PII) of vendors and customers, and could facilitate further stages of an attack chain such as account takeover or lateral movement within the WordPress environment.

## Recommendation

* Update the WCFM Marketplace - Multivendor Marketplace for WooCommerce plugin to the latest version that addresses CVE-2026-18442.
* Deploy the provided Sigma rule to web server access logs to detect potential exploitation attempts.
* Review web server access logs for HTTP requests containing SQL injection patterns such as comments (--), union statements, or common escape characters within the 'wcfmmp_user_location_lng' parameter.
