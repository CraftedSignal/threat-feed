---
title: WP AutoSuggest 0.24 SQL Injection Vulnerability (CVE-2018-25434)
slug: 2026-06-wp-autosuggest-sql-injection
description: WP AutoSuggest version 0.24 contains an SQL injection vulnerability that allows an unauthenticated attacker to execute arbitrary SQL queries by injecting malicious code through the wpas_keys parameter via GET requests to autosuggest.php, potentially extracting sensitive database information.
date: "2026-06-01T22:18:49Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - wordpress
  - cve-2018-25434
vendors:
  - WordPress
products:
  - WP AutoSuggest
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25434
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25434
  - https://kaimi.io
  - https://wordpress.org/plugins/wp-autosuggest/
  - https://www.exploit-db.com/exploits/45977
  - https://www.vulncheck.com/advisories/wp-autosuggest-sql-injection-via-autosuggest-php
rules:
  - title: Detect CVE-2018-25434 Exploitation — WP AutoSuggest SQL Injection Attempt
    description: Detects CVE-2018-25434 exploitation — HTTP GET requests to autosuggest.php with SQL injection attempts in the wpas_keys parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Potential SQL Injection via common bypasses in WP AutoSuggest
    description: Detects potential SQL Injection attempts in the wpas_keys parameter of autosuggest.php by looking for URL encoded characters
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

WP AutoSuggest 0.24 is vulnerable to SQL injection. An unauthenticated attacker can send a specially crafted GET request to the `autosuggest.php` endpoint, injecting malicious SQL code into the `wpas_keys` parameter. This can lead to the execution of arbitrary SQL queries, potentially allowing the attacker to read sensitive data from the WordPress database. The vulnerability was reported in CVE-2018-25434 and has a CVSS v3.1 score of 8.2, indicating a high severity due to the potential for unauthorized data access. This issue poses a significant risk to WordPress sites using the WP AutoSuggest plugin.

## Attack Chain

1.  The attacker identifies a WordPress site using WP AutoSuggest version 0.24.
2.  The attacker crafts a malicious HTTP GET request targeting the `autosuggest.php` endpoint.
3.  The attacker injects SQL code into the `wpas_keys` parameter of the GET request.
4.  The web server processes the request, passing the malicious SQL code to the database query without proper sanitization.
5.  The database executes the attacker-controlled SQL query.
6.  Sensitive information, such as user credentials or post content, is extracted from the database.
7.  The extracted data is returned to the attacker in the HTTP response.
8.  The attacker uses the obtained information for further malicious activities, such as account takeover or data exfiltration.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25434) allows an unauthenticated attacker to execute arbitrary SQL queries on the affected WordPress database. This can lead to the disclosure of sensitive information, including user credentials, database configurations, and content of WordPress posts. The number of potential victims is dependent on the number of WordPress sites running the vulnerable WP AutoSuggest plugin version 0.24. If successful, an attacker can gain complete control over the WordPress site's data.

## Recommendation

*   Upgrade the WP AutoSuggest plugin to a version that addresses the SQL injection vulnerability (CVE-2018-25434).
*   Deploy the Sigma rule "Detect CVE-2018-25434 Exploitation — WP AutoSuggest SQL Injection Attempt" to your SIEM and tune it for your environment.
*   Monitor web server logs for suspicious GET requests to `autosuggest.php` containing potentially malicious SQL code in the `wpas_keys` parameter.
