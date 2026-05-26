---
title: SourceCodester Hospitals Patient Records Management System SQL Injection Vulnerability (CVE-2026-9355)
slug: 2026-05-sourcecodester-sqli
description: SourceCodester Hospitals Patient Records Management System version 1.0 is vulnerable to SQL injection (CVE-2026-9355) via the ID parameter in the /classes/Master.php?f=save_patient_history endpoint, allowing a remote attacker to execute arbitrary SQL queries.
date: "2026-05-26T13:44:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-9355
  - web-application
vendors:
  - SourceCodester
products:
  - Hospitals Patient Records Management System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9355
    cvss: 7.3
    epss: 0.0003
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9355
  - https://github.com/yan-124/yan/issues/3
  - https://vuldb.com/submit/813020
  - https://vuldb.com/vuln/365318
  - https://vuldb.com/vuln/365318/cti
  - https://www.sourcecodester.com/
rules:
  - title: Detect CVE-2026-9355 Exploitation Attempt — SQL Injection in SourceCodester Hospitals Patient Records Management System
    description: Detects CVE-2026-9355 exploitation attempt — SQL injection attempts targeting the /classes/Master.php endpoint in SourceCodester Hospitals Patient Records Management System
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9355 Exploitation Attempt — SQL Injection via POST
    description: Detects CVE-2026-9355 exploitation attempt — SQL injection in POST data targeting /classes/Master.php?f=save_patient_history
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

SourceCodester Hospitals Patient Records Management System 1.0 is vulnerable to SQL injection. The vulnerability, identified as CVE-2026-9355, resides in the `/classes/Master.php?f=save_patient_history` file.  A remote attacker can exploit this vulnerability by manipulating the `ID` argument in a request.  The vulnerability allows for the execution of arbitrary SQL commands. Public exploit code is available. This vulnerability poses a significant risk to organizations using the affected software, potentially leading to data breaches, data manipulation, and unauthorized access to sensitive patient information.

## Attack Chain

1.  The attacker identifies a vulnerable instance of SourceCodester Hospitals Patient Records Management System 1.0.
2.  The attacker crafts a malicious HTTP request targeting the `/classes/Master.php?f=save_patient_history` endpoint.
3.  The attacker injects SQL code into the `ID` parameter of the HTTP request.
4.  The application fails to properly sanitize the input, passing the malicious SQL code to the database.
5.  The database executes the injected SQL code.
6.  The attacker retrieves sensitive data from the database, such as patient records or administrative credentials.
7.  The attacker uses the retrieved credentials to gain unauthorized access to the application.
8.  The attacker modifies, deletes, or exfiltrates patient data, causing significant damage to the organization.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-9355) in SourceCodester Hospitals Patient Records Management System 1.0 can lead to unauthorized access to sensitive patient data, including personal information, medical history, and financial details. This can result in data breaches, regulatory fines, reputational damage, and potential legal liabilities. The vulnerability allows attackers to read, modify, or delete data, potentially affecting a large number of patients.

## Recommendation

*   Apply input validation and sanitization to the `ID` parameter in `/classes/Master.php?f=save_patient_history` to prevent SQL injection attacks.
*   Deploy the Sigma rule "Detect CVE-2026-9355 Exploitation Attempt" to detect malicious requests targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious activity, such as SQL injection attempts targeting `/classes/Master.php?f=save_patient_history`, using the "Detect CVE-2026-9355 Exploitation Attempt" Sigma rule.
*   Implement a web application firewall (WAF) to filter out malicious requests targeting the vulnerable endpoint.
*   Update the SourceCodester Hospitals Patient Records Management System to a patched version as soon as it becomes available.
