---
title: SourceCodester Advanced School Management System SQL Injection Vulnerability
slug: 2026-05-asms-sqli
description: A SQL injection vulnerability (CVE-2026-7545) exists in SourceCodester Advanced School Management System 1.0 within the checkEmail endpoint of commonController.php, allowing remote attackers to potentially execute arbitrary SQL commands.
date: "2026-05-01T02:16:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - vulnerability
  - web-application
vendors:
  - SourceCodester
products:
  - Advanced School Management System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7545
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7545
  - https://github.com/eqwerwq/CVE/issues/2
  - https://vuldb.com/vuln/360356
rules:
  - title: Detect ASMS CheckEmail SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the checkEmail endpoint in SourceCodester Advanced School Management System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ASMS CommonController Access
    description: Detects access to the commonController.php file, which is associated with a SQL injection vulnerability in SourceCodester Advanced School Management System.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SourceCodester Advanced School Management System version 1.0 is vulnerable to SQL injection in the `checkEmail` endpoint within the `commonController.php` file. This vulnerability, identified as CVE-2026-7545, allows a remote attacker to inject arbitrary SQL commands. Publicly available exploits targeting this vulnerability increase the risk of exploitation. Successful exploitation could lead to unauthorized data access, modification, or deletion within the application's database. Given the availability of public exploits, organizations using this software are at an elevated risk.

## Attack Chain

1.  The attacker identifies the `checkEmail` endpoint in `commonController.php`.
2.  The attacker crafts a malicious HTTP request to the `checkEmail` endpoint, injecting SQL code into the email parameter.
3.  The vulnerable application fails to properly sanitize the email input.
4.  The injected SQL code is passed directly to the database query.
5.  The database executes the malicious SQL code.
6.  The attacker gains unauthorized access to the database.
7.  The attacker may then read sensitive data, modify existing data, or insert new malicious data.
8.  The attacker might also use this to escalate privileges within the application.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-7545) could allow an attacker to read, modify, or delete sensitive data stored in the Advanced School Management System database. This could include student records, financial information, or administrative credentials. The availability of public exploits increases the likelihood of attacks targeting this vulnerability, potentially impacting any organization using the affected software.

## Recommendation

*   Apply input validation and sanitization to the `checkEmail` endpoint in `commonController.php` to prevent SQL injection attacks.
*   Deploy the Sigma rule `Detect ASMS CheckEmail SQL Injection Attempt` to identify exploitation attempts in web server logs.
*   Monitor web server logs for suspicious activity related to the `checkEmail` endpoint.
