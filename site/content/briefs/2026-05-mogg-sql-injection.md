---
title: MOGG web simulator Script SQL Injection Vulnerability (CVE-2018-25422)
slug: 2026-05-mogg-sql-injection
description: MOGG web simulator Script is vulnerable to SQL injection (CVE-2018-25422), allowing unauthenticated attackers to execute arbitrary SQL commands via the id parameter in play.php, potentially leading to sensitive data extraction.
date: "2026-05-30T16:21:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve
products:
  - MOGG web simulator Script
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25422
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25422
  - https://github.com/spider312/mtgas
  - https://www.exploit-db.com/exploits/45717
  - https://www.vulncheck.com/advisories/mogg-web-simulator-script-all-version-sql-injection-via-play-php
rules:
  - title: Detect MOGG Web Simulator SQL Injection Attempt
    description: Detects CVE-2018-25422 exploitation — attempts to exploit SQL injection in MOGG web simulator's play.php via GET requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect MOGG Web Simulator - play.php Access
    description: Detects access to the play.php page which may indicate potential exploitation activity
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

MOGG web simulator Script is susceptible to an SQL injection vulnerability (CVE-2018-25422). Unauthenticated attackers can exploit this flaw by injecting malicious SQL code through the `id` parameter in the `play.php` script. Successful exploitation allows attackers to execute arbitrary SQL commands, potentially enabling them to extract sensitive database information, including usernames and other confidential data. The vulnerability poses a significant risk as it requires no authentication, making it easily exploitable by remote attackers. This vulnerability was reported on 2026-05-30.

## Attack Chain

1. An attacker identifies the vulnerable `play.php` script within the MOGG web simulator.
2. The attacker crafts a malicious SQL payload designed to extract data or manipulate the database.
3. The attacker sends a GET request to `play.php`, embedding the SQL payload in the `id` parameter (e.g., `play.php?id=1'+UNION+SELECT+username,password+FROM+users--`).
4. The web application fails to properly sanitize the input from the `id` parameter.
5. The application executes the attacker's injected SQL code against the database.
6. The database processes the malicious query and returns the requested sensitive information.
7. The attacker captures the database response containing the extracted data (e.g., usernames, passwords).
8. The attacker uses the extracted data for further malicious activities, such as unauthorized access or data breaches.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to the exposure of sensitive data, including usernames, passwords, and potentially other confidential information stored in the database. An attacker could leverage this access to compromise user accounts, gain unauthorized access to the system, or perform further malicious activities. Given the unauthenticated nature of the vulnerability, the risk is significantly elevated, potentially impacting all users of the MOGG web simulator Script.

## Recommendation

*   Apply appropriate input validation and sanitization to the `id` parameter in `play.php` to prevent SQL injection attacks.
*   Deploy the Sigma rule `Detect MOGG Web Simulator SQL Injection Attempt` to identify and block malicious requests targeting the vulnerable `play.php` script.
*   Monitor web server logs for suspicious GET requests to `play.php` containing SQL injection payloads.
*   Consider using parameterized queries or prepared statements to prevent SQL injection vulnerabilities.
