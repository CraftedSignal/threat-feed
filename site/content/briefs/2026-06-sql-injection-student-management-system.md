---
title: SQL Injection Vulnerability in student_management_system_by_php (CVE-2026-10225)
slug: 2026-06-sql-injection-student-management-system
description: A SQL injection vulnerability exists in raisulislamg4's student_management_system_by_php up to commit 310d950e09013d5133c6b9210aff9444382d16d1, allowing remote attackers to execute arbitrary SQL commands by manipulating the Username argument in login_check.php.
date: "2026-06-01T06:17:43Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - sql-injection
  - vulnerability
  - web-application
products:
  - student_management_system_by_php
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-10225
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10225
rules:
  - title: Detect SQL Injection Attempts in Login Check
    description: Detects potential SQL injection attempts in the Username parameter of login_check.php based on common SQL syntax.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Anomalous SQL Queries
    description: Detects potentially malicious SQL queries based on unusual syntax or commands.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-10225, has been discovered in the raisulislamg4 student_management_system_by_php. This vulnerability affects versions up to commit 310d950e09013d5133c6b9210aff9444382d16d1. The vulnerability is located within the login_check.php file, specifically in the Login component, where the Username argument is susceptible to SQL injection. A remote attacker can exploit this vulnerability to execute arbitrary SQL commands on the system. The exploit is now public, increasing the risk of active exploitation. The project was notified but has not responded, and due to the rolling release model, specific affected versions are not available.

## Attack Chain

1.  The attacker identifies a student_management_system_by_php instance running a vulnerable version.
2.  The attacker crafts a malicious HTTP request targeting the login_check.php file.
3.  The request includes a manipulated 'Username' parameter containing SQL injection payloads (e.g., `admin' OR '1'='1'--`).
4.  The vulnerable login_check.php script processes the crafted 'Username' parameter without proper sanitization.
5.  The unsanitized input is incorporated into a SQL query executed against the database.
6.  The injected SQL code manipulates the query logic, potentially bypassing authentication.
7.  The attacker gains unauthorized access to the system with elevated privileges.
8.  The attacker may then proceed to exfiltrate sensitive data, modify database records, or escalate privileges further to compromise the entire system.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-10225) allows a remote attacker to execute arbitrary SQL commands. This can lead to unauthorized access to sensitive student data, modification or deletion of records, and complete compromise of the database server. Given that the exploit is public, student_management_system_by_php installations are at high risk of being targeted. The lack of a timely patch exacerbates the threat.

## Recommendation

*   Inspect web server logs for suspicious POST requests to `login_check.php` with potentially malicious SQL syntax in the `Username` parameter to detect exploitation attempts (see Sigma rule "Detect SQL Injection Attempts in Login Check").
*   Implement input validation and sanitization on the 'Username' parameter in `login_check.php` to prevent SQL injection.
*   Monitor database logs for unusual SQL queries originating from the web application (see Sigma rule "Detect Anomalous SQL Queries").
*   Apply security best practices for SQL database configuration, including principle of least privilege.
*   Upgrade to a patched version of student_management_system_by_php as soon as one is released.
