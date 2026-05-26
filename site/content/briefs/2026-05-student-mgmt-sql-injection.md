---
title: SQL Injection Vulnerability in StudentManagementSystem
slug: 2026-05-student-mgmt-sql-injection
description: A SQL injection vulnerability exists in the /success.php file of yashpokharna2555 StudentManagementSystem, allowing remote attackers to execute arbitrary SQL commands by manipulating the User argument.
date: "2026-05-26T14:22:51Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
vendors:
  - yashpokharna2555
products:
  - StudentManagementSystem
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-9469
    cvss: 7.3
    epss: 0.0003
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9469
rules:
  - title: Detects CVE-2026-9469 Exploitation — SQL Injection in StudentManagementSystem
    description: Detects CVE-2026-9469 exploitation — SQL injection attempts in the /success.php endpoint by looking for SQL keywords in the User parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects Suspicious GET Request to success.php
    description: Detects suspicious GET requests to the success.php endpoint which may indicate reconnaissance or exploitation attempts.
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

A SQL injection vulnerability has been identified in the StudentManagementSystem developed by yashpokharna2555. The vulnerability resides within the `/success.php` file and is triggered by manipulating the `User` argument. This allows a remote attacker to inject arbitrary SQL commands, potentially leading to unauthorized data access, modification, or deletion. The vulnerability is publicly known and could be exploited in attacks. The project was notified of the issue but has not yet responded. Due to the project's use of continuous delivery, specific affected and updated versions are not available.

## Attack Chain

1.  The attacker identifies the `/success.php` endpoint in the StudentManagementSystem.
2.  The attacker crafts a malicious HTTP request targeting `/success.php`.
3.  The crafted request includes a `User` parameter containing SQL injection payload.
4.  The application processes the request without proper sanitization of the `User` parameter.
5.  The unsanitized input is incorporated into an SQL query.
6.  The injected SQL code is executed against the database.
7.  The attacker gains unauthorized access to sensitive data, such as student records or administrative credentials.
8.  The attacker may further escalate privileges or compromise other parts of the system.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to severe consequences, including unauthorized access to sensitive student data, modification of records, or complete compromise of the StudentManagementSystem database. This could result in significant reputational damage, financial loss, and legal repercussions for the affected organization. The exact number of potential victims is unknown, but any organization using this vulnerable system is at risk.

## Recommendation

*   Inspect web server logs for suspicious requests to `/success.php` containing SQL injection payloads in the `User` parameter (see rule "Detects CVE-2026-9469 Exploitation — SQL Injection in StudentManagementSystem").
*   Deploy a web application firewall (WAF) rule to block requests with SQL injection attempts targeting the `/success.php` endpoint.
*   Apply input validation and sanitization techniques to the `User` parameter in `/success.php` to prevent SQL injection.
*   Monitor database logs for unusual activity that may indicate successful SQL injection attempts.
