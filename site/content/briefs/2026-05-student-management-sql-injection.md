---
title: STUDENT-MANAGEMENT-SYSTEM SQL Injection Vulnerability (CVE-2026-10111)
slug: 2026-05-student-management-sql-injection
description: A flaw in sambitraj STUDENT-MANAGEMENT-SYSTEM 1.0 allows a remote attacker to perform SQL injection by manipulating the email argument on the Login Page, potentially leading to unauthorized data access.
date: "2026-05-30T08:17:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql injection
  - cve-2026-10111
  - web application
vendors:
  - sambitraj
products:
  - STUDENT-MANAGEMENT-SYSTEM 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-10111
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10111
  - https://github.com/sambitraj/STUDENT-MANAGEMENT-SYSTEM/
  - https://github.com/sambitraj/STUDENT-MANAGEMENT-SYSTEM/issues/2
  - https://vuldb.com/submit/818539
  - https://vuldb.com/vuln/367289
  - https://vuldb.com/vuln/367289/cti
rules:
  - title: Detect SQL Injection Attempts in STUDENT-MANAGEMENT-SYSTEM Login
    description: Detects CVE-2026-10111 exploitation - SQL injection attempts in the email parameter of the login page.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Error Responses to Possible SQLi Attempts on Login
    description: Detects unusual error responses that may be related to SQL injection attempts against the login page.
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

A SQL injection vulnerability, tracked as CVE-2026-10111, has been identified in sambitraj STUDENT-MANAGEMENT-SYSTEM version 1.0. The vulnerability resides within the Login Page component, specifically affecting how the application handles the 'email' argument. A remote attacker can exploit this vulnerability by manipulating the 'email' parameter in a request, potentially gaining unauthorized access to sensitive data stored in the underlying database. The vulnerability has a CVSS v3.1 score of 7.3, indicating a high severity. An exploit is publicly available, increasing the risk of widespread exploitation. The vendor was notified through an issue report, but has not responded yet.

## Attack Chain

1.  An attacker identifies the Login Page of the STUDENT-MANAGEMENT-SYSTEM 1.0 application.
2.  The attacker crafts a malicious HTTP request targeting the Login Page.
3.  Within the request, the attacker injects SQL code into the 'email' argument.
4.  The application processes the crafted request without proper sanitization or escaping of the SQL code.
5.  The injected SQL code is executed against the database.
6.  The attacker retrieves sensitive data from the database, such as usernames, passwords, or other student information.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-10111) can lead to unauthorized access to sensitive student data, including personally identifiable information (PII). The attacker could potentially modify or delete data, leading to data integrity issues and service disruption. Given the publicly available exploit, the risk of widespread exploitation is elevated, potentially impacting a large number of student records and the overall reputation of the institution using the vulnerable system.

## Recommendation

*   Inspect web server logs for suspicious POST requests to the login page with SQL injection attempts in the 'email' parameter. Deploy the Sigma rule `Detect SQL Injection Attempts in STUDENT-MANAGEMENT-SYSTEM Login` to identify potential exploitation.
*   Upgrade to a patched version of STUDENT-MANAGEMENT-SYSTEM that addresses CVE-2026-10111 or implement input validation and sanitization for the 'email' parameter on the Login Page.
*   Implement a web application firewall (WAF) rule to block requests containing common SQL injection payloads targeting the login page.
*   Monitor network traffic for unusual database activity originating from the web server, indicating potential data exfiltration following successful SQL injection.
