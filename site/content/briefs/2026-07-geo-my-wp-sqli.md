---
title: 'CVE-2026-15300: Critical SQL Injection in GEO my WP WordPress Plugin'
slug: 2026-07-geo-my-wp-sqli
description: A critical SQL Injection vulnerability, identified as CVE-2026-15300, was found in the GEO my WP plugin for WordPress, affecting versions up to and including 4.5.4, allowing attackers to inject SQL payloads through the 'distance', 'lat', and 'lng' parameters, leading to potential data compromise or denial of service.
date: "2026-07-10T05:18:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - sql-injection
  - vulnerability
  - webserver
vendors:
  - GEO my WP
  - WordPress
products:
  - GEO my WP plugin <= 4.5.4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The GEO my WP plugin for WordPress was vulnerable to SQL Injection via the 'distance', 'lat', and 'lng' parameters
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: payloads such as `1 OR SLEEP(3)` survived sanitization ... interpolated into unquoted numeric positions in the proximity-search query
    confidence_band: high
cves:
  - id: CVE-2026-15300
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15300
rules:
  - title: Detect CVE-2026-15300 Exploitation - GEO my WP SQL Injection
    description: Detects CVE-2026-15300 exploitation - SQL Injection attempts against the GEO my WP WordPress plugin via 'distance', 'lat', or 'lng' parameters with common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical SQL Injection vulnerability, CVE-2026-15300, has been identified in the GEO my WP plugin for WordPress, affecting versions up to and including 4.5.4. This flaw allows unauthenticated attackers to inject malicious SQL payloads through the 'distance', 'lat', and 'lng' parameters within HTTP GET requests. The vulnerability stems from values being read directly from `$_SERVER['QUERY_STRING']` via `parse_str()`, which bypasses standard WordPress input sanitization functions like `wp_magic_quotes`. Although these values were subsequently passed through `esc_sql()`, this function inadequately sanitized the input for its eventual interpolation into unquoted numeric positions within the plugin's proximity-search queries. This allowed payloads such as `1 OR SLEEP(3)` to execute successfully on the database. Successful exploitation could lead to information disclosure, denial of service, or potentially remote code execution on the underlying database server. The issue was patched in version 4.5.5 by introducing `is_numeric()` checks and `(float)` casts for the affected parameters.

## Attack Chain

1. An attacker identifies a WordPress website running a vulnerable version of the GEO my WP plugin (version 4.5.4 or earlier).
2. The attacker crafts an HTTP GET request targeting a vulnerable endpoint of the GEO my WP plugin, appending a malicious SQL payload to the `distance`, `lat`, or `lng` URL parameters (e.g., `/wp-admin/admin-ajax.php?action=gmw_get_locations&distance=1%20OR%20SLEEP(3)`).
3. The vulnerable plugin code processes the request, reading the crafted parameters directly from `$_SERVER['QUERY_STRING']` via `parse_str()`, thereby bypassing `wp_magic_quotes` which would typically mitigate such injection attempts.
4. The `esc_sql()` function is applied to the parameter values; however, it fails to adequately sanitize the malicious payload because the input is destined for unquoted *numeric* positions within the subsequent SQL query, allowing payloads like `OR SLEEP(3)` to persist.
5. The unsanitized SQL payload is directly interpolated into the `HAVING` or `SELECT` clause of the database's proximity-search query (e.g., `SELECT ..., (some_calc) AS distance FROM ... HAVING distance BETWEEN 0 AND 1 OR SLEEP(3)`).
6. The backend database server executes the injected SQL command, leading to the attacker's desired effect, such as delaying the response to cause a denial of service, or executing more complex queries for data exfiltration or remote code execution.

## Impact

Successful exploitation of CVE-2026-15300 can lead to severe consequences for affected WordPress sites. Attackers can leverage SQL injection to gain unauthorized access to sensitive data stored in the database, including user credentials, personal information, and website configurations. Depending on the database configuration and the specific injected payload, attackers might achieve full database compromise, data manipulation, or even remote code execution on the underlying server. Furthermore, denial-of-service attacks, such as those employing `SLEEP()` commands, can significantly degrade website performance or render it temporarily unavailable, severely disrupting business operations and damaging organizational reputation. While specific victim counts are not provided, the widespread use of WordPress and its plugins suggests a broad potential impact across various sectors.

## Recommendation

* Patch all WordPress installations using the GEO my WP plugin to version 4.5.5 or later to remediate CVE-2026-15300 immediately.
* Deploy the Sigma rule `Detect CVE-2026-15300 Exploitation - GEO my WP SQL Injection` to your SIEM to detect attempted exploitation of this vulnerability.
* Enable comprehensive web server access logging, including full URI query strings, to allow for detection and forensic analysis of exploitation attempts.
* Implement a Web Application Firewall (WAF) in front of WordPress instances to filter and block suspicious requests targeting `distance`, `lat`, or `lng` parameters with SQL injection payloads.
