---
title: PHPGurukul Daily Expense Tracking System SQL Injection Vulnerability
slug: 2026-04-php-gurukul-sqli
description: A remote SQL injection vulnerability exists in PHPGurukul Daily Expense Tracking System 1.1 within the /register.php file, where manipulation of the email argument allows for arbitrary SQL command execution, with a public exploit available.
date: "2026-04-14T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sqli
  - cve-2026-6193
  - php
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6193
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6193
  - https://github.com/f1rstb100d/CVE/issues/47
  - https://vuldb.com/vuln/357115
rules:
  - title: Detect Suspicious SQL Injection Attempts in PHPGurukul Registration
    description: Detects potential SQL injection attempts targeting the /register.php endpoint of PHPGurukul Daily Expense Tracking System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PHPGurukul Registration Page Access
    description: Detects access to the PHPGurukul Daily Expense Tracking System registration page, which may indicate reconnaissance or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security flaw has been identified in PHPGurukul Daily Expense Tracking System version 1.1. This vulnerability resides in the `/register.php` file and is triggered by manipulating the `email` argument. Successful exploitation enables remote SQL injection, potentially granting attackers unauthorized access to sensitive database information or allowing them to modify data. This vulnerability, identified as CVE-2026-6193, has a CVSS v3.1 score of 7.3, indicating a high level of severity. The existence of a publicly available exploit increases the risk of widespread exploitation. Organizations using this software should take immediate action to mitigate the risk.

## Attack Chain

1.  An attacker identifies a vulnerable instance of PHPGurukul Daily Expense Tracking System 1.1.
2.  The attacker crafts a malicious HTTP request targeting the `/register.php` endpoint.
3.  Within the request, the attacker injects SQL code into the `email` parameter.
4.  The application fails to properly sanitize the input, passing the malicious SQL query to the database.
5.  The database executes the injected SQL code, potentially allowing the attacker to read, modify, or delete data.
6.  The attacker may leverage the initial SQL injection to escalate privileges within the database.
7.  The attacker could potentially gain access to administrative credentials stored in the database.
8.  Finally, the attacker uses the compromised credentials to gain full control over the application.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to severe consequences. Attackers could gain unauthorized access to sensitive user data, including usernames, passwords, and financial information. This could result in identity theft, financial fraud, and reputational damage for both the organization and its users. The attacker could also modify or delete data, disrupt the application's functionality, or even gain complete control of the server. Given the availability of a public exploit, the likelihood of attacks is significantly increased.

## Recommendation

*   Apply any available patches or updates provided by PHPGurukul to address CVE-2026-6193.
*   Deploy the Sigma rule "Detect Suspicious SQL Injection Attempts in PHPGurukul Registration" to identify exploitation attempts targeting the `/register.php` endpoint.
*   Implement input validation and sanitization measures on the `email` parameter in `/register.php` to prevent SQL injection.
*   Monitor web server logs for suspicious activity, such as unusual characters or SQL syntax in the `email` parameter, which could indicate an attempted SQL injection (webserver log source).
*   Implement a Web Application Firewall (WAF) rule to block requests containing SQL injection payloads targeting `/register.php`.
