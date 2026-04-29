---
title: SuiteCRM 7.10.7 Time-Based SQL Injection Vulnerability
slug: 2026-04-suitecrm-sqli
description: SuiteCRM 7.10.7 is vulnerable to time-based SQL injection in the record parameter of the Users module DetailView action, allowing authenticated attackers to manipulate database queries and potentially extract sensitive information.
date: "2026-04-05T21:16:43Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sql-injection
  - cve-2019-25664
  - suitecrm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25664
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25664
  - https://www.exploit-db.com/exploits/46311
  - https://www.vulncheck.com/advisories/suitecrm-sql-injection-via-record-parameter
rules:
  - title: SuiteCRM SQL Injection Attempt via URI
    description: Detects potential SQL injection attempts in SuiteCRM by monitoring for suspicious keywords in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: SuiteCRM SQL Injection Attempt via POST Data
    description: Detects potential SQL injection attempts in SuiteCRM by monitoring for suspicious keywords in POST data.
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

SuiteCRM 7.10.7 is susceptible to a time-based SQL injection vulnerability (CVE-2019-25664) affecting the `record` parameter within the `Users` module's `DetailView` action. This flaw enables authenticated attackers to inject arbitrary SQL code into database queries by manipulating the `record` parameter within GET requests directed to the `index.php` endpoint. By exploiting this vulnerability, attackers can leverage time-based blind SQL injection techniques to extract sensitive database information. This vulnerability poses a significant risk to organizations utilizing vulnerable versions of SuiteCRM as it can lead to unauthorized access to sensitive data.

## Attack Chain

1. An attacker authenticates to the SuiteCRM application.
2. The attacker crafts a malicious GET request targeting the `index.php` endpoint.
3. The attacker injects SQL code into the `record` parameter of the GET request, specifically targeting the `Users` module's `DetailView` action.
4. The SuiteCRM application processes the crafted request without proper sanitization of the `record` parameter.
5. The injected SQL code is executed within the context of the database query.
6. The attacker leverages time-based SQL injection techniques to infer information about the database structure and content by observing the response times.
7. Sensitive data is extracted from the database through repeated time-based injection attacks.
8. The attacker exfiltrates the extracted data.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to the unauthorized disclosure of sensitive data stored within the SuiteCRM database. The scope of the impact depends on the level of access granted to the compromised user account, but could include customer data, financial information, or other confidential business data. While there is no count on victims available, all SuiteCRM 7.10.7 installations are vulnerable.

## Recommendation

*   Upgrade to a patched version of SuiteCRM that addresses CVE-2019-25664 to remediate the SQL injection vulnerability.
*   Deploy the Sigma rule provided below to detect exploitation attempts targeting the vulnerable `index.php` endpoint.
*   Implement input validation and sanitization measures within the SuiteCRM application to prevent SQL injection attacks.
*   Monitor web server logs for suspicious GET requests containing potentially malicious SQL code in the `record` parameter.
