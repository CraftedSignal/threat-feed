---
title: SQL Injection Vulnerability in SourceCodester Class and Exam Timetabling System (CVE-2026-15597)
slug: 2026-07-sourcecodester-sqli
description: A critical SQL injection vulnerability (CVE-2026-15597) in SourceCodester Class and Exam Timetabling System version 1.0 allows remote, unauthenticated attackers to manipulate the 'ID' argument in `/edit_exam2.php`, potentially leading to unauthorized data access, modification, or complete system compromise, with a public exploit available.
date: "2026-07-13T22:19:53Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - sqli
  - web-vulnerability
  - cve
  - remote-code-execution
vendors:
  - SourceCodester
products:
  - Class and Exam Timetabling System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A security flaw has been discovered in SourceCodester Class and Exam Timetabling System 1.0/2.php. ... The attack can be initiated remotely. The exploit has been released to the public and may be used for attacks.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1580
    technique_name: Stolen Credential Collection
    evidence: Performing a manipulation of the argument ID results in sql injection.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Performing a manipulation of the argument ID results in sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-15597
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15597
  - https://github.com/asdasddqwdq29-a11y/new-cve/issues/1
  - https://vuldb.com/cve/CVE-2026-15597
  - https://vuldb.com/submit/855298
  - https://vuldb.com/vuln/378112
  - https://vuldb.com/vuln/378112/cti
  - https://www.sourcecodester.com/
iocs:
  - type: url
    value: https://github.com/asdasddqwdq29-a11y/new-cve/issues/1
  - type: url
    value: https://vuldb.com/cve/CVE-2026-15597
  - type: url
    value: https://vuldb.com/vuln/378112
  - type: url
    value: https://vuldb.com/vuln/378112/cti
ioc_counts:
  url: 4
rules:
  - title: Detects CVE-2026-15597 Exploitation - SQL Injection in /edit_exam2.php
    description: Detects exploitation attempts of CVE-2026-15597, an SQL injection vulnerability in SourceCodester Class and Exam Timetabling System 1.0, by identifying suspicious characters in the 'ID' parameter of requests to /edit_exam2.php.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1580
    data_sources:
      - webserver
rules_count: 1
---

A significant security flaw, identified as CVE-2026-15597, has been discovered in SourceCodester Class and Exam Timetabling System version 1.0. This vulnerability specifically impacts the `/edit_exam2.php` file, where improper handling of the `ID` argument can be exploited for SQL injection. The flaw allows remote, unauthenticated attackers to manipulate database queries, leading to unauthorized access, modification, or deletion of sensitive information within the system. The NVD reports that an exploit for this vulnerability has been publicly released, increasing the risk of active exploitation. Organizations utilizing this system should consider it a critical threat due to the ease of exploitation and potential for severe data compromise.

## Attack Chain

1. **Initial Reconnaissance**: An attacker identifies an internet-facing instance of the SourceCodester Class and Exam Timetabling System 1.0.
2. **Vulnerability Identification**: The attacker targets the `/edit_exam2.php` endpoint, recognizing its potential for parameter manipulation.
3. **Payload Crafting**: A malicious SQL injection payload is crafted, designed to manipulate the `ID` argument in HTTP GET or POST requests.
4. **Exploitation Attempt**: The attacker sends an HTTP request to `/edit_exam2.php`, embedding the SQL injection payload within the `ID` parameter.
5. **Database Interaction**: The vulnerable application processes the malicious `ID` argument directly into a backend SQL query without proper sanitization.
6. **Data Exfiltration/Manipulation**: The crafted SQL query is executed by the database, allowing the attacker to read, modify, or delete sensitive database entries.
7. **Impact**: The attacker gains unauthorized access to application data, potentially leading to privilege escalation or complete system compromise.

## Impact

Successful exploitation of CVE-2026-15597 can lead to severe consequences for organizations using the SourceCodester Class and Exam Timetabling System. Attackers can gain unauthorized access to the application's underlying database, potentially exfiltrating sensitive student, faculty, and examination data. This could include personal identifiable information (PII), academic records, and administrative credentials. Data integrity may also be compromised through unauthorized modification or deletion of records, disrupting academic operations and leading to data loss. Given that the exploit is publicly available, a wide range of educational institutions or any entity using this specific software are at risk, making them targets for data theft and service disruption.

## Recommendation

* **Patch CVE-2026-15597**: Immediately apply any available patches or vendor-provided mitigations for SourceCodester Class and Exam Timetabling System 1.0, specifically addressing CVE-2026-15597.
* **Deploy the Sigma rule**: Implement the provided Sigma rule to detect attempts at SQL injection against `/edit_exam2.php` by monitoring web server logs.
* **Block malicious requests**: Configure Web Application Firewalls (WAFs) to block HTTP requests containing SQL injection payloads targeting `edit_exam2.php` and its `ID` argument.
* **Monitor vendor updates**: Regularly check https://www.sourcecodester.com/ and related security advisories for updates and security patches.
