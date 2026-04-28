---
title: manikandan580 School-management-system SQL Injection Vulnerability
slug: 2026-04-school-management-sqli
description: A time-based blind SQL injection vulnerability in manikandan580 School-management-system 1.0 allows unauthenticated attackers to potentially execute arbitrary SQL queries and gain unauthorized access to sensitive information.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - sqli
  - cve-2025-65135
  - school-management-system
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-65135
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-65135
  - https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2025-65135
rules:
  - title: Detect SQL Injection Attempts via POST to between-date-reprtsdetails.php
    description: Detects potential SQL injection attempts targeting the fromdate parameter in the between-date-reprtsdetails.php script.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages in Web Server Logs
    description: Detects SQL injection attempts by identifying common database error messages in web server logs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical time-based blind SQL injection vulnerability, identified as CVE-2025-65135, affects version 1.0 of the manikandan580 School-management-system. This vulnerability resides in the `/studentms/admin/between-date-reprtsdetails.php` script and is exploitable through the `fromdate` POST parameter. Given the nature of the vulnerability, attackers can potentially bypass authentication and execute arbitrary SQL queries on the back-end database. Successful exploitation could lead to unauthorized access to sensitive student data, administrative credentials, and other confidential information managed by the school system. This vulnerability poses a significant risk to educational institutions utilizing the affected software.

## Attack Chain

1.  An unauthenticated attacker identifies the `/studentms/admin/between-date-reprtsdetails.php` endpoint.
2.  The attacker crafts a malicious HTTP POST request targeting the `/studentms/admin/between-date-reprtsdetails.php` endpoint.
3.  The POST request includes a manipulated `fromdate` parameter containing a time-based blind SQL injection payload (e.g., `fromdate=1' AND SLEEP(5) -- -`).
4.  The server-side application processes the crafted SQL query without proper sanitization.
5.  The injected SQL payload executes a `SLEEP()` function or equivalent based on database type, causing a delay in the server's response if the injected condition is true.
6.  The attacker monitors the server response time to infer the results of the injected SQL query.
7.  The attacker uses the blind SQL injection technique to extract sensitive data from the database, such as usernames, passwords, and student records, character by character.
8.  The attacker uses the obtained credentials to gain unauthorized administrative access to the School-management-system, leading to potential data breaches and system compromise.

## Impact

Successful exploitation of CVE-2025-65135 could result in a complete compromise of the manikandan580 School-management-system. Attackers could gain access to personally identifiable information (PII) of students, financial records, and other sensitive data. This data could be used for identity theft, financial fraud, or extortion. The vulnerable system could also be used as a launchpad for further attacks against other systems within the network. Due to the potential for widespread data breaches, this vulnerability represents a critical risk for schools and educational institutions using the affected software.

## Recommendation

*   Apply any available patches or updates released by manikandan580 to address CVE-2025-65135.
*   Implement input validation and sanitization measures to prevent SQL injection attacks on the `fromdate` POST parameter in `/studentms/admin/between-date-reprtsdetails.php`.
*   Deploy the Sigma rules provided in this brief to detect exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious POST requests to `/studentms/admin/between-date-reprtsdetails.php` containing SQL injection payloads.
*   Consider using a Web Application Firewall (WAF) to filter out malicious requests targeting the vulnerable application.
