---
title: WeePie Cookie Allow Plugin SQL Injection Vulnerability
slug: 2026-05-weepie-sqli
description: The WeePie Cookie Allow plugin for WordPress is vulnerable to SQL Injection via the 'consent' parameter in versions up to 3.4.11, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2026-05-05T14:16:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sqli
  - wordpress
  - plugin
  - cve-2026-4304
vendors:
  - WeePie
products:
  - WeePie Cookie Allow plugin for WordPress <= 3.4.11
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-4304
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4304
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/f783e626-37c0-4ad9-9074-c5332583a0cb?source=cve
rules:
  - title: Detect SQL Injection Attempts in WeePie Cookie Allow 'consent' Parameter
    description: Detects potential SQL injection attempts targeting the 'consent' parameter in the WeePie Cookie Allow plugin for WordPress.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress WeePie Plugin SQLi via URI
    description: Detects SQL Injection attempts on WordPress WeePie Plugin.
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

The WeePie Cookie Allow plugin for WordPress, a widely used plugin for managing cookie consent, contains a critical SQL Injection vulnerability. This flaw, identified as CVE-2026-4304, affects all versions up to and including 3.4.11. The vulnerability stems from insufficient input sanitization of the 'consent' parameter, combined with inadequate preparation of the SQL queries used by the plugin. This allows unauthenticated attackers to inject malicious SQL code into the application's database queries, potentially leading to sensitive data extraction. Given the plugin's popularity, a successful exploit could expose a significant number of WordPress sites to data breaches and other malicious activities.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP request targeting a WordPress site running the vulnerable WeePie Cookie Allow plugin.
2. The attacker injects SQL code into the 'consent' parameter of the HTTP request. This is typically a GET or POST request.
3. The WordPress site receives the request and passes the tainted 'consent' parameter to the WeePie Cookie Allow plugin.
4. The WeePie Cookie Allow plugin processes the malicious 'consent' parameter without proper sanitization or escaping.
5. The plugin incorporates the unsanitized input into an SQL query.
6. The database executes the attacker-controlled SQL query, potentially extracting sensitive data such as user credentials, configuration details, or other confidential information.
7. The extracted data is returned to the attacker.
8. The attacker can use the stolen information to further compromise the WordPress site or the underlying server.

## Impact

Successful exploitation of this SQL Injection vulnerability (CVE-2026-4304) can lead to the unauthorized disclosure of sensitive information, including user credentials and database contents. Given the widespread use of the WeePie Cookie Allow plugin, a large number of WordPress websites are potentially vulnerable. This could lead to significant data breaches, defacement of websites, and further compromise of affected systems. A CVSS v3.1 score of 7.5 indicates a high level of severity.

## Recommendation

*   Upgrade the WeePie Cookie Allow plugin to the latest version, which includes a patch for CVE-2026-4304.
*   Deploy the provided Sigma rules to detect potential exploitation attempts targeting the 'consent' parameter.
*   Monitor web server logs for suspicious requests containing SQL injection patterns in the 'consent' parameter, as detected by the Sigma rules.
*   Consider implementing a web application firewall (WAF) rule to block requests containing SQL injection attempts targeting the 'consent' parameter.
