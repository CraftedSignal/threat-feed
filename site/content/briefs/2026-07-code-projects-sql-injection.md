---
title: 'CVE-2026-14705: SQL Injection in code-projects Online Examination 1.0'
slug: 2026-07-code-projects-sql-injection
description: A critical remote SQL injection vulnerability (CVE-2026-14705) exists in code-projects Online Examination 1.0, specifically within the `head.php` file, where manipulation of the `uname` or `password` arguments can lead to arbitrary SQL command execution, which has been publicly disclosed and can be exploited by an unauthenticated attacker.
date: "2026-07-05T06:25:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve
  - initial-access
vendors:
  - code-projects
products:
  - Online Examination 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability was determined in code-projects Online Examination 1.0. ... Executing a manipulation of the argument uname/password can lead to sql injection. It is possible to launch the attack remotely. The exploit has been publicly disclosed and may be utilized.
    confidence_band: high
cves:
  - id: CVE-2026-14705
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14705
  - https://vuldb.com/cve/CVE-2026-14705
  - https://github.com/zzzxc643/CVE1/blob/main/project1/vul1.md
rules:
  - title: Detects CVE-2026-14705 Exploitation - SQL Injection in head.php
    description: Detects exploitation attempts for CVE-2026-14705, an SQL injection vulnerability in code-projects Online Examination 1.0's head.php, by looking for SQL metacharacters in uname or password parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A remote SQL injection vulnerability, identified as CVE-2026-14705, has been discovered in version 1.0 of the code-projects Online Examination web application. This flaw resides within the `head.php` component, where insufficient sanitization of the `uname` (username) and `password` arguments allows an attacker to inject arbitrary SQL commands. This can lead to unauthorized data access, modification, or potential control over the database, thereby compromising the integrity and confidentiality of the examination system. The vulnerability is network-exploitable and does not require authentication, making it a significant risk. The exploit for this vulnerability has been publicly disclosed, increasing the likelihood of its utilization by malicious actors, and necessitating immediate attention from organizations running this specific software version.

## Attack Chain

1.  An unauthenticated attacker identifies a publicly accessible instance of `code-projects Online Examination 1.0`.
2.  The attacker crafts a malicious HTTP request (GET or POST) targeting the `head.php` endpoint of the application.
3.  Within the HTTP request, the attacker injects SQL metacharacters and commands into the `uname` or `password` parameters.
4.  The vulnerable `head.php` script processes the request without adequately sanitizing the input fields.
5.  The backend database executes the attacker's injected SQL commands, often leading to authentication bypass, data exfiltration, or further database manipulation.
6.  The attacker gains unauthorized access to the application's functionality, database records, or potentially elevates privileges within the database context.

## Impact

Successful exploitation of CVE-2026-14705 could lead to severe consequences for organizations using code-projects Online Examination 1.0. Attackers can bypass authentication mechanisms, access sensitive student or exam data (e.g., personally identifiable information, test scores, questions), and potentially alter or delete critical database records. This could result in data breaches, academic fraud, reputational damage, and regulatory non-compliance. Given the public disclosure of the exploit, any internet-facing instance of the affected application is at immediate risk of exploitation, potentially affecting an unknown number of educational institutions or businesses using this platform.

## Recommendation

*   Immediately remove `code-projects Online Examination 1.0` from production environments or apply vendor-provided patches as soon as they become available to mitigate CVE-2026-14705.
*   Implement strong input validation and parameterized queries for all user-supplied input, especially for the `uname` and `password` fields, to prevent SQL injection attacks.
*   Deploy a Web Application Firewall (WAF) in front of web applications to detect and block malicious requests attempting to exploit CVE-2026-14705, specifically looking for SQL injection payloads.
*   Deploy the Sigma rule provided in this brief to your SIEM solution to detect attempted exploitation of this vulnerability.
