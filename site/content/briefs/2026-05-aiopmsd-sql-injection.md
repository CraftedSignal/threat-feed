---
title: AiOPMSD Final 1.0.0 SQL Injection Vulnerability (CVE-2018-25418)
slug: 2026-05-aiopmsd-sql-injection
description: AiOPMSD Final 1.0.0 is vulnerable to SQL injection (CVE-2018-25418) via the `year` parameter in `year.php`, allowing unauthenticated attackers to execute arbitrary SQL queries and extract sensitive information.
date: "2026-05-30T16:20:34Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - cve-2018-25418
  - web-application
vendors:
  - AiOPMSD
products:
  - AiOPMSD Final 1.0.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
cves:
  - id: CVE-2018-25418
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25418
  - https://aiopmsd.sourceforge.io/
  - https://sourceforge.net/projects/aiopmsd/files/latest/download
  - https://www.exploit-db.com/exploits/45690
  - https://www.vulncheck.com/advisories/aiopmsd-final-sql-injection-via-year-php
rules:
  - title: Detect AiOPMSD SQL Injection Attempt via Year Parameter
    description: Detects CVE-2018-25418 exploitation — SQL injection attempts in AiOPMSD Final 1.0.0 by monitoring the `year` parameter for suspicious characters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
  - title: Detect AiOPMSD Version Disclosure via SQL Injection
    description: Detects CVE-2018-25418 exploitation — Attempts to retrieve database version information via SQL injection in the `year` parameter.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
rules_count: 2
---

AiOPMSD Final 1.0.0 is susceptible to an SQL injection vulnerability (CVE-2018-25418) that allows unauthenticated attackers to execute arbitrary SQL queries. The vulnerability exists within the `year.php` script and can be exploited by injecting malicious SQL code into the `year` parameter via a GET request. Successful exploitation allows attackers to extract sensitive database information, including usernames, database names, and version details. This poses a significant risk as it could lead to complete database compromise and further malicious activities. The vulnerability was reported in 2026, but the CVE was assigned in 2018.

## Attack Chain

1.  An unauthenticated attacker identifies an AiOPMSD Final 1.0.0 instance.
2.  The attacker crafts a malicious SQL payload designed to extract sensitive database information.
3.  The attacker sends a GET request to `/year.php` with the crafted SQL payload injected into the `year` parameter (e.g., `year.php?year=malicious_sql_payload`).
4.  The `year.php` script processes the GET request and concatenates the `year` parameter value into an SQL query without proper sanitization.
5.  The malicious SQL query is executed against the AiOPMSD database.
6.  The database returns results based on the injected SQL code, potentially including usernames, database names, and version information.
7.  The attacker receives the database response containing the extracted sensitive information.
8.  The attacker uses the extracted information for further malicious activities, such as gaining unauthorized access or compromising other systems.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25418) allows unauthenticated attackers to extract sensitive information from the AiOPMSD Final 1.0.0 database. This can lead to the exposure of usernames, passwords, database configurations, and other confidential data. The CVSS v3.1 base score is 8.2, indicating a high severity vulnerability. This could lead to full database compromise and unauthorized access to the affected system.

## Recommendation

*   Deploy the Sigma rule `Detect AiOPMSD SQL Injection Attempt via Year Parameter` to identify potential exploitation attempts by monitoring for suspicious characters in the `cs-uri-query` field in web server logs.
*   Apply input validation and sanitization to the `year` parameter in the `year.php` script to prevent SQL injection attacks, according to secure coding practices.
*   Restrict access to the AiOPMSD database from untrusted networks.
*   Monitor web server logs for any unusual activity or requests to `year.php` that contain suspicious SQL syntax.
*   Review and update the AiOPMSD Final 1.0.0 codebase for other potential vulnerabilities.
