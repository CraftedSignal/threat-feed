---
title: SQL Injection in SourceCodester Class and Exam Timetabling System (CVE-2026-14641)
slug: 2026-07-sql-injection-sourcecodester
description: A critical vulnerability, CVE-2026-14641, in SourceCodester Class and Exam Timetabling System version 1.0 allows for remote SQL injection via the 'ID' argument in the '/edit_course.php' file, enabling unauthenticated attackers to manipulate database queries with a publicly disclosed exploit.
date: "2026-07-04T19:23:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve
  - sourcecodester
  - php
vendors:
  - SourceCodester
products:
  - Class and Exam Timetabling System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument ID can lead to sql injection. The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-14641
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14641
  - https://github.com/sunjingyuan123/ccvvee/issues/2
  - https://vuldb.com/cve/CVE-2026-14641
  - https://vuldb.com/submit/846143
  - https://vuldb.com/submit/847955
  - https://vuldb.com/vuln/376157
  - https://vuldb.com/vuln/376157/cti
  - https://www.sourcecodester.com/
rules:
  - title: Detects CVE-2026-14641 Exploitation — SQL Injection in edit_course.php
    description: Detects exploitation attempts of CVE-2026-14641, an SQL injection vulnerability in SourceCodester Class and Exam Timetabling System 1.0 via the 'ID' argument in '/edit_course.php'.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1499
    data_sources:
      - webserver
rules_count: 1
---

A high-severity SQL injection vulnerability, tracked as CVE-2026-14641, has been identified in SourceCodester Class and Exam Timetabling System version 1.0. This flaw allows unauthenticated, remote attackers to execute arbitrary SQL commands by manipulating the 'ID' argument within the `/edit_course.php` file. The vulnerability stems from improper neutralization of special elements in SQL commands, specifically CWE-89. The exploit has been publicly disclosed and is actively available, increasing the risk of widespread exploitation. This vulnerability enables attackers to potentially read, modify, or delete data from the backend database, compromising data confidentiality and integrity. Defenders should prioritize patching and implementing robust input validation to mitigate this threat.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious HTTP GET request targeting the `/edit_course.php` endpoint of the vulnerable SourceCodester Class and Exam Timetabling System.
2.  The crafted request includes a specially malformed `ID` parameter in the URL query string, containing SQL injection payloads (e.g., `ID=1%27%20UNION%20SELECT%20...`).
3.  The vulnerable `/edit_course.php` script processes the `ID` parameter without proper input sanitization or validation.
4.  The application directly embeds the malicious `ID` parameter's value into a backend SQL query.
5.  The database server executes the manipulated SQL query, which may bypass intended logic and allow the attacker to retrieve sensitive information or modify data.
6.  The web server responds to the attacker's request, potentially disclosing sensitive database content (e.g., user credentials, system configurations, application data) within the HTTP response body.
7.  The attacker parses the HTTP response to extract the compromised data, achieve data exfiltration, or modify database records.

## Impact

Successful exploitation of CVE-2026-14641 can lead to significant data breaches, where attackers can read, modify, or delete sensitive information stored in the application's database. This includes user accounts, academic records, scheduling data, and potentially administrative credentials. While specific victim counts are not available, the widespread use of SourceCodester systems in educational settings suggests that successful attacks could impact student and staff privacy, disrupt academic operations, and lead to reputational damage for affected institutions. The CVSS 3.1 score of 7.3 (High) indicates low impact on confidentiality, integrity, and availability, but SQL injection commonly leads to more severe consequences like full database compromise or even arbitrary code execution under certain configurations.

## Recommendation

*   Prioritize patching SourceCodester Class and Exam Timetabling System to a non-vulnerable version immediately to address CVE-2026-14641.
*   Deploy the provided Sigma rule to your SIEM solution to detect exploitation attempts against the `/edit_course.php` endpoint.
*   Ensure webserver logging (category: `webserver`) is enabled and configured to capture full HTTP request details, especially `cs-uri-stem` and `cs-uri-query`, to enable the rule.
*   Implement web application firewalls (WAFs) with rules designed to detect and block SQL injection payloads targeting HTTP GET parameters.
