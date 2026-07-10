---
title: QueryMine SMS SQL Injection Vulnerability (CVE-2026-6490)
slug: 2024-01-21-querymine-sqli
description: A remote SQL injection vulnerability exists in QueryMine sms up to version 7ab5a9ea196209611134525ffc18de25c57d9593 within the admin/deletecourse.php file, caused by improper handling of the ID GET request parameter, potentially leading to unauthorized data access or modification.
date: "2024-01-21T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-6490
  - querymine
vendors:
  - QueryMine
products:
  - QueryMine SMS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6490
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6490
rules:
  - title: Detect SQL Injection Attempt in QueryMine deletecourse.php
    description: Detects potential SQL injection attempts targeting the ID parameter in QueryMine's deletecourse.php.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect potential SQL Injection in QueryMine via URI encoding
    description: Detects possible SQL injection attempts in QueryMine through URI encoded payloads
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-6490, has been discovered in QueryMine sms, affecting versions up to 7ab5a9ea196209611134525ffc18de25c57d9593. The vulnerability resides in the `admin/deletecourse.php` file and is triggered by manipulating the `ID` GET request parameter.  Successful exploitation allows a remote attacker to inject arbitrary SQL commands. This vulnerability has a publicly available exploit, which significantly increases the likelihood of exploitation. Due to the rolling release model of QueryMine, specific affected versions are not clearly defined. The vendor was notified but did not respond. This poses a significant risk, potentially enabling attackers to compromise sensitive data and system integrity.

## Attack Chain

1. An attacker identifies a vulnerable QueryMine SMS instance running a version up to 7ab5a9ea196209611134525ffc18de25c57d9593.
2. The attacker crafts a malicious HTTP GET request targeting the `admin/deletecourse.php` file.
3. The crafted request includes a manipulated `ID` parameter containing SQL injection payloads.
4. The web server processes the request and passes the malicious `ID` parameter to the vulnerable SQL query without proper sanitization.
5. The injected SQL code is executed against the database, potentially allowing the attacker to bypass authentication and access sensitive data.
6. The attacker may extract user credentials, course data, or other confidential information.
7. The attacker could modify or delete data within the database.
8. The attacker could potentially use the SQL injection to gain further access to the server or escalate privileges.

## Impact

Successful exploitation of this vulnerability could lead to unauthorized access to sensitive student and administrative data, modification or deletion of critical course information, and potential compromise of the entire QueryMine SMS system. Given that publicly available exploit code exists, the risk of widespread exploitation is elevated. The lack of specific versioning information makes identifying vulnerable installations challenging. If successful, this could allow an attacker to use the database server as an entry point into the network.

## Recommendation

*   Inspect web server access logs for suspicious GET requests to `admin/deletecourse.php` containing unusual characters or SQL keywords in the `ID` parameter; deploy the provided Sigma rule to detect this activity.
*   Implement input validation and sanitization measures for the `ID` parameter in `admin/deletecourse.php` to mitigate SQL injection vulnerabilities.
*   Monitor web server logs for SQL errors originating from the `admin/deletecourse.php` script, which could indicate attempted exploitation.
*   Since patching information is unavailable, consider web application firewall (WAF) rules to filter out malicious SQL injection attempts targeting the `ID` parameter.
