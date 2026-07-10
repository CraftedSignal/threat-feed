---
title: DirectoryPress WordPress Plugin Vulnerable to SQL Injection (CVE-2026-3489)
slug: 2024-05-16-directorypress-sqli
description: The DirectoryPress WordPress plugin before 3.6.26 is vulnerable to unauthenticated SQL Injection via the 'packages' parameter, allowing attackers to extract sensitive database information.
date: "2024-05-16T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - sql-injection
  - cve-2026-3489
  - directorypress
vendors:
  - DirectoryPress
  - WordPress
products:
  - DirectoryPress
  - WordPress
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-3489
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3489
rules:
  - title: Detect Suspicious GET Requests to WordPress Plugins with SQL Injection Attempts
    description: Detects suspicious GET requests to WordPress plugins that may be indicative of SQL injection attempts by identifying common SQL injection keywords in the query string.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect DirectoryPress SQL Injection Attempt via Packages Parameter
    description: Detects SQL injection attempts targeting the DirectoryPress plugin's 'packages' parameter by identifying common SQL keywords within the request URI.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The DirectoryPress plugin, a WordPress plugin designed for business directory and classified ad listings, is susceptible to a critical SQL Injection vulnerability. This flaw, identified as CVE-2026-3489, affects versions up to and including 3.6.26. The vulnerability resides in the 'packages' parameter and stems from inadequate input sanitization and insufficient preparation of existing SQL queries. This allows unauthenticated attackers to inject arbitrary SQL commands into database queries. Successful exploitation could lead to the extraction of sensitive information from the WordPress database. Given the widespread use of WordPress and the DirectoryPress plugin, this vulnerability poses a significant risk to organizations using affected versions.

## Attack Chain

1. An unauthenticated attacker identifies a DirectoryPress installation running a vulnerable version (<= 3.6.26).
2. The attacker crafts a malicious HTTP request targeting a script using the 'packages' parameter.
3. The attacker injects SQL code into the 'packages' parameter within the HTTP request.
4. The vulnerable application fails to properly sanitize the input, passing the malicious SQL code to the database.
5. The injected SQL code is executed within the context of the existing database query.
6. The attacker leverages the SQL injection to extract sensitive data, such as usernames, passwords, or other confidential information.
7. The extracted data is returned to the attacker in the HTTP response.
8. The attacker uses the stolen credentials to gain unauthorized access to the WordPress administration panel or other systems.

## Impact

Successful exploitation of this SQL Injection vulnerability (CVE-2026-3489) can lead to the complete compromise of the WordPress database. Attackers can steal sensitive information, including user credentials, customer data, and proprietary business information. This can result in significant financial losses, reputational damage, and legal liabilities. The impact is magnified by the potential for attackers to gain administrative access to the WordPress site, allowing them to further compromise the server and connected systems.

## Recommendation

*   Immediately update the DirectoryPress plugin to the latest version to patch CVE-2026-3489.
*   Deploy the Sigma rule "Detect Suspicious GET Requests to WordPress Plugins with SQL Injection Attempts" to identify potential exploitation attempts targeting the 'packages' parameter.
*   Implement a Web Application Firewall (WAF) to filter malicious requests and prevent SQL injection attacks.
*   Review and harden WordPress database security configurations, including limiting database user privileges and enabling query parameter validation.
