---
title: SQL Injection Vulnerability in projectworlds hospital-management-system-in-php 1.0 (CVE-2026-8785)
slug: 2026-05-hospital-management-sql-injection
description: A SQL injection vulnerability (CVE-2026-8785) exists in the getAllPatientDetail function of the update_info.php file in projectworlds hospital-management-system-in-php version 1.0, allowing remote attackers to execute arbitrary SQL commands via the 'appointment_no' GET parameter.
date: "2026-05-18T04:17:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - sql-injection
  - webapp
vendors:
  - projectworlds
products:
  - hospital-management-system-in-php 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8785
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8785
rules:
  - title: Detect CVE-2026-8785 Exploitation via SQL Injection
    description: Detects CVE-2026-8785 exploitation — SQL injection attempts targeting the appointment_no parameter in update_info.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SQL Injection Characters in HTTP GET Parameters
    description: Detects generic SQL injection attempts in HTTP GET requests based on presence of SQL syntax characters.
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

A SQL injection vulnerability, identified as CVE-2026-8785, has been discovered in projectworlds hospital-management-system-in-php version 1.0. The vulnerability resides within the `getAllPatientDetail` function in the `update_info.php` file. A remote attacker can exploit this flaw by manipulating the `appointment_no` GET parameter. The vendor has been notified, but has not yet responded or provided a patch. Publicly available exploits exist, making this vulnerability a significant risk.

## Attack Chain

1.  The attacker identifies an instance of projectworlds hospital-management-system-in-php version 1.0.
2.  The attacker crafts a malicious HTTP GET request targeting the `update_info.php` file.
3.  The attacker injects SQL code into the `appointment_no` parameter of the GET request.
4.  The webserver processes the request and passes the `appointment_no` parameter to the `getAllPatientDetail` function without proper sanitization.
5.  The injected SQL code is executed against the database.
6.  The attacker retrieves sensitive data from the database, such as patient records or credentials.
7.  The attacker may modify or delete data within the database.
8.  The attacker may use the compromised database to further compromise the system or other connected systems.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary SQL commands. This can lead to the disclosure of sensitive patient data, modification or deletion of records, and potential compromise of the entire application and underlying database server. Given the nature of the application, this could result in severe breaches of patient privacy, financial losses, and reputational damage for the affected healthcare organization.

## Recommendation

*   Inspect web server logs for suspicious GET requests to `update_info.php` containing SQL syntax in the `appointment_no` parameter and deploy the "Detect CVE-2026-8785 Exploitation via SQL Injection" Sigma rule.
*   Apply input validation and sanitization to the `appointment_no` parameter in the `getAllPatientDetail` function to prevent SQL injection. Contact the vendor for a patch or apply a hotfix.
*   Monitor database logs for unauthorized access or modification attempts originating from the web server.
*   Implement the "Detect SQL Injection Characters in HTTP GET Parameters" Sigma rule to broadly detect potential SQL injection attempts.
