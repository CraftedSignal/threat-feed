---
title: ManageEngine PAM360 and Password Manager Pro Authenticated SQL Injection Vulnerability (CVE-2026-5785)
slug: 2026-04-manageengine-sqli
description: An authenticated SQL injection vulnerability (CVE-2026-5785) in the query report module of Zohocorp ManageEngine PAM360 versions before 8531 and ManageEngine Password Manager Pro versions from 8600 to 13230 allows attackers with low privileges to potentially read or modify sensitive database information.
date: "2026-04-17T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - cve-2026-5785
  - sqli
  - manageengine
  - pam360
  - passwordmanagerpro
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1565
    technique_name: Data Staged
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5785
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5785
  - https://www.manageengine.com/products/passwordmanagerpro/advisory/cve-2026-5785.html
rules:
  - title: Detect ManageEngine SQL Injection Attempts via Web Logs
    description: Detects potential SQL injection attempts against ManageEngine PAM360 or Password Manager Pro based on suspicious SQL syntax in web server logs.
    platform: sigma
    severity: high
    tactics:
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ManageEngine Password Manager Pro SQL Injection in Request Body
    description: Detects potential SQL injection attempts against ManageEngine Password Manager Pro based on suspicious SQL syntax in web request bodies.
    platform: sigma
    severity: high
    tactics:
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Zohocorp ManageEngine PAM360 and Password Manager Pro are affected by an authenticated SQL injection vulnerability within the query report module. This vulnerability, identified as CVE-2026-5785, impacts PAM360 versions prior to 8531 and Password Manager Pro versions ranging from 8600 to 13230. An attacker with valid, albeit low-privileged, credentials can exploit this flaw by injecting malicious SQL queries through the affected module. Successful exploitation could lead to unauthorized data access, modification, or even complete database compromise. Defenders must apply the necessary patches to remediate this vulnerability.

## Attack Chain

1.  Attacker gains valid, low-privileged credentials to ManageEngine PAM360 or Password Manager Pro application.
2.  Attacker authenticates to the ManageEngine application with the obtained credentials.
3.  Attacker navigates to the "query report" module within the application's interface.
4.  Attacker crafts a malicious SQL query containing SQL injection payloads within report generation parameters.
5.  The application processes the crafted SQL query without proper sanitization, executing the injected SQL commands.
6.  The database executes the malicious SQL query, leading to unintended data retrieval (exfiltration) or modification.
7.  Attacker extracts sensitive information like usernames, passwords, or configuration details from the database.
8.  Attacker may further exploit the SQL injection to modify database records, escalate privileges, or compromise other application functionalities.

## Impact

Successful exploitation of CVE-2026-5785 can result in significant data breaches and compromise of sensitive assets managed by ManageEngine PAM360 and Password Manager Pro. An attacker could potentially gain unauthorized access to credentials, configuration settings, and other critical information stored within the database. The impact can range from data theft and service disruption to complete system compromise, potentially affecting hundreds of organizations relying on these products for privileged access management.

## Recommendation

*   Immediately upgrade ManageEngine PAM360 to version 8531 or later to patch CVE-2026-5785.
*   Immediately upgrade ManageEngine Password Manager Pro to a version later than 13230, or a version earlier than 8600.
*   Monitor web server logs for suspicious SQL syntax or unusual database query patterns related to the query report module using the provided Sigma rule.
*   Implement input validation and sanitization measures within the ManageEngine application to prevent SQL injection attacks.
*   Enable database auditing to detect and investigate any unauthorized database access or modification attempts stemming from CVE-2026-5785.
