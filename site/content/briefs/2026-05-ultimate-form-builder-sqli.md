---
title: WordPress Ultimate Form Builder Lite Plugin SQL Injection Vulnerability
slug: 2026-05-ultimate-form-builder-sqli
description: WordPress Ultimate Form Builder Lite plugin version 1.3.7 and below contains an SQL injection vulnerability (CVE-2018-25352) that allows authenticated attackers to manipulate database queries by injecting SQL code through the entry_id POST parameter, potentially leading to privilege escalation.
date: "2026-05-26T13:41:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - wordpress
  - plugin
  - CVE-2018-25352
vendors:
  - WordPress
products:
  - Ultimate Form Builder Lite plugin <= 1.3.7
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2018-25352
    cvss: 7.1
    epss: 0.00024
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25352
rules:
  - title: Detect CVE-2018-25352 Exploitation Attempt — WordPress Ultimate Form Builder SQLi
    description: Detects CVE-2018-25352 exploitation attempt — HTTP POST request to admin-ajax.php with ufbl_get_entry_detail_action and SQL injection attempts in entry_id parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect WordPress admin-ajax.php SQL Injection Payload
    description: Detects generic SQL injection attempts via the WordPress admin-ajax.php endpoint. Useful as a broad catch-all for various plugin vulnerabilities.
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

The WordPress Ultimate Form Builder Lite plugin, specifically versions 1.3.7 and below, is vulnerable to SQL injection. This vulnerability (CVE-2018-25352) allows authenticated attackers to inject malicious SQL code via the `entry_id` POST parameter. By crafting specific POST requests to the `admin-ajax.php` endpoint with the action `ufbl_get_entry_detail_action`, attackers can manipulate database queries to extract sensitive information, modify existing data, or potentially escalate their privileges within the WordPress database. Successful exploitation could lead to complete compromise of the WordPress installation.

## Attack Chain

1. An attacker authenticates to the WordPress application.
2. The attacker crafts a malicious HTTP POST request targeting the `admin-ajax.php` endpoint.
3. The POST request includes the `action` parameter set to `ufbl_get_entry_detail_action`.
4. The attacker injects SQL code into the `entry_id` POST parameter.
5. The vulnerable plugin processes the `entry_id` parameter without proper sanitization, incorporating the injected SQL code into a database query.
6. The crafted SQL query is executed against the WordPress database.
7. Depending on the injected SQL code, the attacker can extract sensitive data, modify database entries, or create new administrative accounts.
8. The attacker leverages the gained access to compromise the entire WordPress installation.

## Impact

Successful exploitation of this SQL injection vulnerability allows attackers to read, modify, or delete arbitrary data within the WordPress database. This can lead to sensitive data leakage, defacement of the website, or complete takeover of the WordPress installation. Depending on the attacker's goals, they may escalate privileges to create new administrative accounts, inject malicious code into the website, or use the compromised server as a staging point for further attacks.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2018-25352 Exploitation Attempt — WordPress Ultimate Form Builder SQLi` to identify potentially malicious requests targeting the vulnerable endpoint and parameter.
*   Upgrade the Ultimate Form Builder Lite plugin to a version greater than 1.3.7 to patch the CVE-2018-25352 vulnerability.
*   Monitor web server logs for suspicious POST requests to `admin-ajax.php` with the `ufbl_get_entry_detail_action` action and SQL-like syntax in the `entry_id` parameter.
