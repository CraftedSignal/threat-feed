---
title: SQL Injection Vulnerability in SourceCodester Class and Exam Timetabling System (CVE-2026-16152)
slug: 2026-07-sql-injection-timetabling-system
description: An unauthenticated remote attacker can exploit CVE-2026-16152, a SQL injection vulnerability in SourceCodester Class and Exam Timetabling System version 1.0, by manipulating the `ID` argument within the `/edit_rooma.php` file, potentially leading to unauthorized database access and data compromise, with a public exploit available.
date: "2026-07-18T21:18:11Z"
lastmod: "2026-07-18T21:18:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve
vendors:
  - SourceCodester
products:
  - Class and Exam Timetabling System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability was found in SourceCodester Class and Exam Timetabling System 1.0. Affected is an unknown function of the file /edit_rooma.php. Performing a manipulation of the argument ID results in sql injection. The attack is possible to be carried out remotely.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1537
    technique_name: Data from Information Repositories
    evidence: Performing a manipulation of the argument ID results in sql injection. ...CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L
    confidence_band: high
cves:
  - id: CVE-2026-16152
    cvss: 7.3
  - id: CVE-2026-16154
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16152
  - https://github.com/justconter/cve/issues/6
  - https://vuldb.com/cve/CVE-2026-16152
  - https://vuldb.com/submit/857078
  - https://vuldb.com/vuln/379918
  - https://vuldb.com/vuln/379918/cti
  - https://www.sourcecodester.com/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16154
rules:
  - title: Detects CVE-2026-16152 Exploitation - SQL Injection in /edit_rooma.php
    description: Detects exploitation attempts against CVE-2026-16152, a SQL injection vulnerability in SourceCodester Class and Exam Timetabling System 1.0, by monitoring HTTP requests for suspicious SQL metacharacters in the 'ID' parameter of the /edit_rooma.php endpoint.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-18T21:18:35Z"
    level: L2
    summary: added CVE-2026-16154
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-16154
---

A high-severity SQL injection vulnerability, identified as CVE-2026-16152, has been discovered in SourceCodester Class and Exam Timetabling System version 1.0. This flaw allows an unauthenticated, remote attacker to execute arbitrary SQL commands by manipulating the `ID` argument within the `/edit_rooma.php` file. The vulnerability stems from improper neutralization of special elements used in SQL commands. The exploit for this vulnerability has been made public, significantly increasing the risk of widespread exploitation. Organizations using this system are at risk of unauthorized data access, modification, or deletion from the backend database, potentially leading to data breaches and integrity issues.

## Attack Chain

1. **Initial Access**: An attacker identifies a publicly exposed instance of SourceCodester Class and Exam Timetabling System version 1.0.
2. **Request Crafting**: The attacker crafts a malicious HTTP GET or POST request targeting the `/edit_rooma.php` endpoint on the vulnerable server.
3. **Payload Delivery**: The crafted HTTP request includes an SQL injection payload embedded within the `ID` URL parameter.
4. **Vulnerability Trigger**: The application processes the `ID` parameter without adequate input sanitization, leading to the attacker's SQL payload being directly incorporated into and executed by the backend database query.
5. **Database Interaction**: The injected SQL commands are executed by the database server, allowing the attacker to bypass authentication and execute arbitrary database operations.
6. **Data Compromise**: The attacker gains unauthorized read access to sensitive data, modifies existing data, or deletes records from the application's database.
7. **Final Objective**: The attacker achieves data exfiltration, data manipulation, or could potentially cause denial of service by corrupting database integrity.

## Impact

Successful exploitation of CVE-2026-16152 can result in significant data compromise, including unauthorized access to confidential information, modification of critical system data, or deletion of database records. Given the nature of a timetabling and exam system, this could expose student, faculty, and exam-related information, manipulate schedules, or disrupt academic operations. The vulnerability is remotely exploitable without authentication, and a public exploit is available, making affected systems highly susceptible to attacks. The CVSS 3.1 Base Score is 7.3, indicating high severity due to potential confidentiality, integrity, and availability impacts (C:L/I:L/A:L).

## Recommendation

* **Patch CVE-2026-16152** immediately if an official patch is available from SourceCodester.
* **Deploy the Sigma rule** provided in this brief to your SIEM and tune for your environment to detect attempts to exploit CVE-2026-16152.
* **Enable webserver access logging** to capture HTTP request details (method, URI stem, URI query, status code) to provide telemetry for the detection rule.
* **Implement a Web Application Firewall (WAF)** in front of affected instances and configure it to block common SQL injection patterns in URL parameters like `ID` on `/edit_rooma.php`.
* **Regularly audit and sanitize input parameters** in web applications to prevent SQL injection vulnerabilities.
