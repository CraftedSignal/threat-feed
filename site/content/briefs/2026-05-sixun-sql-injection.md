---
title: SQL Injection Vulnerability in Sixun Shanghui Group Business Management System
slug: 2026-05-sixun-sql-injection
description: A SQL injection vulnerability exists in Shenzhen Sixun Software Sixun Shanghui Group Business Management System 10 in the /api/Dinner/PayConfig endpoint, where a remote attacker can manipulate the 'tableno' argument to inject arbitrary SQL commands.
date: "2026-05-26T14:28:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-9544
  - web-application
vendors:
  - Shenzhen Sixun Software
products:
  - Sixun Shanghui Group Business Management System 10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9544
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9544
  - https://ucn9h68n9289.feishu.cn/wiki/A9WcwRkFsijnyIkf6vlcx13znoh
  - https://vuldb.com/submit/815425
  - https://vuldb.com/vuln/365608
  - https://vuldb.com/vuln/365608/cti
rules:
  - title: Detect CVE-2026-9544 Exploitation - Sixun Shanghui SQL Injection
    description: Detects CVE-2026-9544 exploitation - SQL injection attempts in the /api/Dinner/PayConfig endpoint by looking for SQL keywords in the tableno parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
      - T1505.001
    data_sources:
      - webserver
  - title: Detect Suspicious HTTP POST Request to Dinner PayConfig API
    description: Detects suspicious HTTP POST requests to the /api/Dinner/PayConfig API endpoint, which might indicate an exploitation attempt of CVE-2026-9544
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
      - T1505.001
    data_sources:
      - webserver
rules_count: 2
---

A SQL injection vulnerability, tracked as CVE-2026-9544, has been identified in Shenzhen Sixun Software's Sixun Shanghui Group Business Management System version 10. The vulnerability resides in the `/api/Dinner/PayConfig` endpoint and is triggered by manipulating the `tableno` argument. Successful exploitation allows a remote attacker to execute arbitrary SQL commands, potentially leading to unauthorized data access, modification, or deletion. The vulnerability is remotely exploitable, and a public exploit is available, increasing the risk of widespread exploitation. The vendor has not responded to disclosure attempts.

## Attack Chain

1.  Attacker identifies an instance of Sixun Shanghui Group Business Management System 10 exposed to the internet.
2.  Attacker crafts a malicious HTTP request targeting the `/api/Dinner/PayConfig` endpoint.
3.  The crafted request includes a modified `tableno` parameter containing SQL injection payloads.
4.  The application fails to properly sanitize the `tableno` input before using it in an SQL query.
5.  The injected SQL code is executed against the database, granting the attacker control over query execution.
6.  Attacker extracts sensitive information from the database, such as user credentials, financial data, or customer details.
7.  Alternatively, the attacker modifies database records to escalate privileges or disrupt application functionality.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-9544) can have severe consequences. An attacker could gain unauthorized access to sensitive business data, leading to financial loss, reputational damage, and legal liabilities. Modification or deletion of critical data could disrupt business operations and lead to system downtime. Given the lack of vendor response, organizations using the affected software are at significant risk.

## Recommendation

*   Apply input validation and sanitization to the `tableno` parameter in the `/api/Dinner/PayConfig` endpoint to prevent SQL injection attacks.
*   Deploy the Sigma rule `Detect CVE-2026-9544 Exploitation - Sixun Shanghui SQL Injection` to identify attempts to exploit this vulnerability via web server logs.
*   Implement a web application firewall (WAF) with rules to block common SQL injection payloads targeting the `/api/Dinner/PayConfig` endpoint.
*   Regularly monitor web server logs for suspicious activity, including requests with unusual characters or SQL keywords in the `tableno` parameter.
*   Apply the Sigma rule `Detect Suspicious HTTP POST Request to Dinner PayConfig API` to detect possible exploitation attempts.
