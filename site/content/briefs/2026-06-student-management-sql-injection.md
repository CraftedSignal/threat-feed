---
title: SQL Injection Vulnerability in student_management_system_by_php (CVE-2026-10226)
slug: 2026-06-student-management-sql-injection
description: A SQL injection vulnerability (CVE-2026-10226) exists in student_management_system_by_php up to version 310d950e09013d5133c6b9210aff9444382d16d1, allowing remote attackers to execute arbitrary SQL commands by manipulating specific parameters in the delete.php file.
date: "2026-06-01T06:17:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-10226
products:
  - student_management_system_by_php
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-10226
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10226
rules:
  - title: Detect SQL Injection Attempt in student_management_system_by_php delete.php
    description: Detects CVE-2026-10226 exploitation - SQL injection attempts in the delete.php script by looking for common SQL injection syntax in the user_id, course_id, teacher_id, student_id, and application_id parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SQL Injection Attempt with base64 encoded payload
    description: Detects SQL injection attempts where payloads are base64 encoded to bypass simple filtering, based on common SQL syntax found post decoding
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

A SQL injection vulnerability, identified as CVE-2026-10226, has been discovered in the raisulislamg4 student_management_system_by_php. This vulnerability affects versions up to 310d950e09013d5133c6b9210aff9444382d16d1. The flaw resides within the delete.php file and can be exploited by remotely manipulating the user_id, course_id, teacher_id, student_id, or application_id parameters. The vulnerability has been publicly disclosed and a proof-of-concept exploit is available, increasing the risk of exploitation. The vendor was notified but has not responded. This poses a significant risk to organizations using the affected student management system.

## Attack Chain

1. An attacker identifies a vulnerable instance of student_management_system_by_php running a version up to 310d950e09013d5133c6b9210aff9444382d16d1.
2. The attacker crafts a malicious HTTP request targeting the `delete.php` endpoint.
3. The attacker injects SQL code into one or more of the following parameters: `user_id`, `course_id`, `teacher_id`, `student_id`, or `application_id`.
4. The web server processes the `delete.php` script, passing the attacker-controlled input to a vulnerable SQL query without proper sanitization.
5. The injected SQL code modifies the query's behavior, potentially allowing the attacker to bypass authentication or access sensitive data.
6. The database server executes the modified SQL query, performing actions unintended by the application developer.
7. The attacker gains unauthorized access to sensitive information stored in the database.
8. The attacker may be able to further escalate the attack, potentially gaining complete control over the database server or the web application.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-10226) can lead to unauthorized access to sensitive student data, including personally identifiable information (PII), academic records, and financial information. This could result in data breaches, identity theft, and financial losses for both the institution and its students. The impact can range from defacement of the application to complete compromise of the underlying database server.

## Recommendation

*   Inspect web server logs for suspicious requests to `delete.php` with potentially malicious characters in the `user_id`, `course_id`, `teacher_id`, `student_id`, and `application_id` parameters, as described in the overview. Implement the Sigma rule `Detect SQL Injection Attempt in student_management_system_by_php delete.php`.
*   Apply input validation and sanitization to all user-supplied data, especially in the `delete.php` script, to prevent SQL injection attacks.
*   Consider using parameterized queries or stored procedures to prevent SQL injection vulnerabilities within the application.
*   Monitor database logs for anomalous activity that could indicate successful SQL injection attempts.
*   Since there are no version details available, any deployment of student_management_system_by_php should be considered vulnerable.
