---
title: SQL Injection Vulnerability in WordPress WooCommerce Advanced Product Search Plugin (CVE-2026-12753)
slug: 2026-07-wordpress-woo-sqli
description: A SQL Injection vulnerability, CVE-2026-12753, has been identified in the Advance Product Search- Voice & Ajax Search for WooCommerce plugin for WordPress, affecting all versions up to and including 1.4.4. The flaw, caused by insufficient input sanitization of the 's' and 'match' parameters and inadequate SQL query preparation, allows unauthenticated attackers to append arbitrary SQL queries. This enables them to extract sensitive information directly from the database.
date: "2026-07-16T04:19:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - woocommerce
  - sql-injection
  - web-vulnerability
products:
  - Advance Product Search- Voice & Ajax Search for WooCommerce plugin (<= 1.4.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Advance Product Search- Voice & Ajax Search for WooCommerce plugin for WordPress is vulnerable to generic SQL Injection via the 's' and 'match' parameter... This makes it possible for unauthenticated attackers to append additional SQL queries...
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1538
    technique_name: Sensitive Data Exposure
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
    confidence_band: high
cves:
  - id: CVE-2026-12753
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12753
rules:
  - title: Detects CVE-2026-12753 Exploitation - WordPress WooCommerce Plugin SQLi
    description: Detects CVE-2026-12753 exploitation - Unauthenticated SQL injection attempts targeting the 's' or 'match' parameters of the Advance Product Search- Voice & Ajax Search for WooCommerce plugin.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1190
      - T1538
    data_sources:
      - webserver
rules_count: 1
---

The National Vulnerability Database (NVD) has released an advisory for CVE-2026-12753, detailing a high-severity SQL Injection vulnerability within the "Advance Product Search- Voice & Ajax Search for WooCommerce" plugin for WordPress. This flaw impacts all plugin versions up to and including 1.4.4. The root cause is attributed to insufficient escaping of user-supplied data in the 's' and 'match' parameters, coupled with inadequate preparation of existing SQL queries. This critical vulnerability allows unauthenticated attackers to inject arbitrary SQL queries, leading to the extraction of sensitive information from the underlying WordPress database. The vulnerability carries a CVSS v3.1 base score of 7.5, emphasizing the urgent need for mitigation.

## Attack Chain

1. An unauthenticated attacker sends a specially crafted HTTP GET or POST request to a WordPress site utilizing the vulnerable "Advance Product Search- Voice & Ajax Search for WooCommerce" plugin.
2. The malicious request targets plugin functionalities that process the 's' or 'match' parameters, often via AJAX endpoints like `/wp-admin/admin-ajax.php` or specific plugin search URLs.
3. The attacker embeds SQL injection payloads, such as `' UNION SELECT user(), database() -- -` or `' OR 1=1 -- -`, within the 's' or 'match' parameter values.
4. Due to the plugin's insufficient input sanitization and improper handling of SQL queries, the injected malicious payload is directly concatenated and executed as part of the legitimate SQL query.
5. The database processes the combined, attacker-controlled SQL query.
6. The database's response, containing data potentially extracted by the attacker's query (e.g., database version, user hashes, sensitive customer information), is returned to the web server.
7. The WordPress application then includes these database query results within its HTTP response, allowing the unauthenticated attacker to view or retrieve the sensitive data.

## Impact

Successful exploitation of CVE-2026-12753 enables unauthenticated attackers to achieve full database compromise of the affected WordPress site. This can lead to the exfiltration of highly sensitive data, including customer personal identifiable information (PII), payment details (if stored), user account credentials (usernames and hashed passwords for administrators and regular users), and any other proprietary business data stored in the database. Such a breach can result in severe financial penalties, significant reputational damage, loss of customer trust, and potential regulatory non-compliance, severely impacting the affected organization.

## Recommendation

* Patch CVE-2026-12753 immediately by updating the "Advance Product Search- Voice & Ajax Search for WooCommerce" plugin to a version greater than 1.4.4.
* Deploy the Sigma rule "Detects CVE-2026-12753 Exploitation - WordPress WooCommerce Plugin SQLi" to your SIEM solution to detect attempts to exploit this vulnerability.
* Configure web server logging (log source: `webserver` category) to capture full HTTP request details, including `cs-uri-query`, and monitor for suspicious patterns indicative of SQL injection payloads.
