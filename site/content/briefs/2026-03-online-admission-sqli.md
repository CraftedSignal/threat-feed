---
title: SourceCodester Online Admission System 1.0 SQL Injection Vulnerability
slug: 2026-03-online-admission-sqli
description: A SQL injection vulnerability in SourceCodester Online Admission System 1.0 allows remote attackers to execute arbitrary SQL commands by manipulating the 'program' argument in the /programmes.php file.
date: "2026-03-24T04:17:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4625
  - https://github.com/WHOAMI-xiaoyu/CVE/blob/main/CVE_7.md
  - https://vuldb.com/?ctiid.352493
  - https://vuldb.com/?id.352493
  - https://vuldb.com/?submit.775788
  - https://www.sourcecodester.com/
iocs:
  - type: url
    value: https://github.com/WHOAMI-xiaoyu/CVE/blob/main/CVE_7.md
  - type: url
    value: https://vuldb.com/?ctiid.352493
  - type: url
    value: https://vuldb.com/?id.352493
  - type: url
    value: https://vuldb.com/?submit.775788
  - type: url
    value: https://www.sourcecodester.com/
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect SQL Injection Attempts in SourceCodester Online Admission System
    description: Detects potential SQL injection attempts targeting the /programmes.php endpoint in SourceCodester Online Admission System 1.0
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Potential SQL Injection via POST Request to programmes.php
    description: Detects potential SQL injection attempts via POST requests to the /programmes.php endpoint in SourceCodester Online Admission System 1.0
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

SourceCodester Online Admission System 1.0 is vulnerable to SQL injection. The vulnerability, identified as CVE-2026-4625, resides in the /programmes.php file and can be exploited by manipulating the 'program' argument. An unauthenticated remote attacker can inject malicious SQL queries into the application's database interactions, potentially leading to data exfiltration, modification, or deletion. Publicly available exploit code exists, increasing the risk of widespread exploitation. This vulnerability poses a significant threat to organizations using the affected system, as it could compromise sensitive student data and undermine the integrity of the admission process. Defenders need to prioritize patching or mitigating this vulnerability.

## Attack Chain

1.  An unauthenticated attacker identifies the vulnerable `/programmes.php` endpoint.
2.  The attacker crafts a malicious HTTP GET or POST request targeting `/programmes.php`.
3.  The crafted request includes a SQL injection payload within the `program` parameter.
4.  The server-side application fails to properly sanitize or parameterize the input.
5.  The application executes the attacker-controlled SQL query against the database.
6.  The attacker bypasses authentication and authorization controls due to the successful injection.
7.  The attacker extracts sensitive data (e.g., student records, credentials) from the database.
8.  The attacker may modify or delete data, or potentially gain further access to the system.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-4625) can lead to unauthorized access to sensitive student data, including personally identifiable information (PII), academic records, and financial details. Attackers could potentially modify admission records, grant unauthorized access, or even shut down the system, disrupting the admission process. Given that public exploit code is available, organizations using SourceCodester Online Admission System 1.0 are at immediate risk of compromise. The impact includes data breaches, financial losses, and reputational damage.

## Recommendation

*   Inspect web server logs for suspicious requests to `/programmes.php` containing SQL injection attempts in the `program` parameter, activating the "Detect SQL Injection Attempts in SourceCodester Online Admission System" Sigma rule.
*   Apply input validation and sanitization to the 'program' parameter in `/programmes.php` to prevent SQL injection, mitigating CVE-2026-4625.
*   Review and restrict access to the database server from the web server to minimize the impact of successful SQL injection attacks.
