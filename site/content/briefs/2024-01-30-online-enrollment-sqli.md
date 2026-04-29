---
title: SQL Injection Vulnerability in itsourcecode Online Enrollment System 1.0
slug: 2024-01-30-online-enrollment-sqli
description: A remote SQL injection vulnerability exists in itsourcecode Online Enrollment System 1.0 within the Parameter Handler component affecting the `/sms/grades/index.php` file, allowing unauthorized database access and has been publicly disclosed.
date: "2026-03-26T05:16:41Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sqli
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4842
rules:
  - title: Detect SQL Injection Attempt in Online Enrollment System
    description: Detects potential SQL injection attempts targeting the itsourcecode Online Enrollment System via the deptid parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect potential SQL injection via URI
    description: Detects potential SQL injection in URI.
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

A critical SQL injection vulnerability has been identified in itsourcecode Online Enrollment System version 1.0. The vulnerability resides within the Parameter Handler component, specifically affecting the `/sms/grades/index.php` file when handling the `deptid` argument. This flaw allows unauthenticated remote attackers to inject arbitrary SQL commands, potentially leading to unauthorized data access, modification, or deletion. Given the public disclosure of the exploit, the risk of exploitation is significantly elevated. Organizations using this software should apply immediate mitigation measures to prevent potential compromise. The affected software is an Online Enrollment System, likely used by educational institutions.

## Attack Chain

1. An attacker identifies an instance of itsourcecode Online Enrollment System 1.0 exposed to the internet.
2. The attacker crafts a malicious HTTP request targeting `/sms/grades/index.php?view=edit&id=1`.
3. The attacker injects a SQL payload into the `deptid` parameter within the URL.
4. The application fails to properly sanitize the input, passing the malicious SQL query to the database.
5. The database executes the injected SQL code, potentially allowing the attacker to bypass authentication and authorization checks.
6. The attacker retrieves sensitive data from the database, such as user credentials, student records, or financial information.
7. The attacker could modify database records, create new administrative accounts, or delete critical data.
8. The attacker gains complete control of the application and the underlying database server, leading to a full system compromise.

## Impact

Successful exploitation of this vulnerability could lead to a full compromise of the Online Enrollment System. This can result in the theft of sensitive student and faculty data, including personally identifiable information (PII), academic records, and financial details. Attackers could also modify grades, alter enrollment data, or disrupt the system's availability, impacting thousands of students and administrative staff. The vulnerability has a CVSS v3.1 base score of 7.3, indicating a high level of severity.

## Recommendation

*   Deploy the provided Sigma rule to detect suspicious HTTP requests containing SQL injection attempts targeting the `/sms/grades/index.php` endpoint.
*   Implement input validation and sanitization measures within the itsourcecode Online Enrollment System to prevent SQL injection attacks.
*   Restrict access to the database server from the web application server to only necessary accounts and permissions.
*   Monitor web server logs for unusual activity and potential exploitation attempts related to CVE-2026-4842.
