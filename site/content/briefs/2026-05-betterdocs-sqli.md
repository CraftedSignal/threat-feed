---
title: BetterDocs Pro Plugin SQL Injection Vulnerability
slug: 2026-05-betterdocs-sqli
description: The BetterDocs Pro plugin for WordPress is vulnerable to SQL Injection via the `get_current_letter_docs` and `docs_sort_by_letter` AJAX actions, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2026-05-07T06:16:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - wordpress
  - plugin
  - cve-2026-4348
vendors:
  - WordPress
products:
  - BetterDocs Pro plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-4348
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4348
rules:
  - title: Detect BetterDocs Pro SQL Injection Attempt via limit Parameter
    description: Detects potential SQL injection attempts in the BetterDocs Pro plugin by monitoring the limit parameter in AJAX requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect BetterDocs Pro SQL Injection Attempt via admin-ajax.php
    description: Detects potential SQL injection attempts in the BetterDocs Pro plugin by looking for specific SQL keywords in POST requests to wp-admin/admin-ajax.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The BetterDocs Pro plugin for WordPress, a popular solution for knowledge base management, is susceptible to a critical SQL Injection vulnerability. This flaw affects all versions up to and including 3.7.0. The vulnerability resides in the `get_current_letter_docs` and `docs_sort_by_letter` AJAX actions. A critical prerequisite for exploitation is that the Encyclopedia feature must be enabled within the BetterDocs Pro settings panel. Successful exploitation enables unauthenticated attackers to inject arbitrary SQL queries, potentially leading to sensitive data exfiltration from the WordPress database. This poses a significant risk to the confidentiality and integrity of affected WordPress sites.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site using BetterDocs Pro with the Encyclopedia feature enabled.
2.  The attacker crafts a malicious HTTP POST request targeting the `wp-admin/admin-ajax.php` endpoint.
3.  The crafted request includes the `action` parameter set to either `get_current_letter_docs` or `docs_sort_by_letter`.
4.  The attacker injects malicious SQL code into the `limit` POST parameter. This parameter is directly interpolated into a SQL query without proper sanitization using `$wpdb->prepare()`.
5.  The WordPress server processes the request, executing the attacker-controlled SQL query against the database.
6.  The injected SQL query extracts sensitive information, such as user credentials, configuration data, or other confidential content stored in the database.
7.  The extracted data is returned to the attacker in the HTTP response.
8.  The attacker analyzes the exfiltrated data for valuable information.

## Impact

Successful exploitation of this SQL Injection vulnerability can lead to complete compromise of the WordPress database. Attackers can steal sensitive data, including user credentials, API keys, and other confidential information. This could lead to unauthorized access to the WordPress site, data breaches, and potential financial losses. This vulnerability has a CVSS v3.1 base score of 7.5, highlighting the significant risk it poses.

## Recommendation

*   Upgrade the BetterDocs Pro plugin to a version greater than 3.7.0 to patch CVE-2026-4348.
*   Deploy the Sigma rule "Detect BetterDocs Pro SQL Injection Attempt via limit Parameter" to your SIEM to detect exploitation attempts targeting the vulnerable AJAX actions.
*   Monitor web server logs for suspicious POST requests to `wp-admin/admin-ajax.php` with the `action` parameter set to `get_current_letter_docs` or `docs_sort_by_letter` and potentially malicious SQL code in the `limit` parameter.
