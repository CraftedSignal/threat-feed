---
title: AiOPMSD Final 1.0.0 Unauthenticated SQL Injection Vulnerability (CVE-2018-25419)
slug: 2026-05-aiopmsd-sql-injection
description: AiOPMSD Final 1.0.0 is vulnerable to SQL injection (CVE-2018-25419) in the genre parameter, allowing unauthenticated attackers to execute arbitrary SQL queries and extract sensitive information.
date: "2026-05-30T16:20:47Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - cve-2018-25419
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
cves:
  - id: CVE-2018-25419
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25419
  - https://aiopmsd.sourceforge.io/
  - https://sourceforge.net/projects/aiopmsd/files/latest/download
  - https://www.exploit-db.com/exploits/45690
  - https://www.vulncheck.com/advisories/aiopmsd-final-sql-injection-via-genre-php
rules:
  - title: Detect CVE-2018-25419 Exploitation — AiOPMSD SQL Injection Attempt
    description: Detects CVE-2018-25419 exploitation — GET requests to genre.php with SQL injection payloads in the genre parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2018-25419 Exploitation — AiOPMSD SQL Injection Attempt with SQL Comments
    description: Detects CVE-2018-25419 exploitation — GET requests to genre.php with SQL injection payloads including comments to bypass sanitization
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

AiOPMSD Final 1.0.0 is susceptible to an SQL injection vulnerability (CVE-2018-25419) that allows unauthenticated attackers to execute arbitrary SQL queries. The vulnerability exists in the `genre` parameter, allowing for malicious code injection through crafted GET requests to `genre.php`. Successful exploitation allows attackers to potentially extract sensitive database information, including usernames, database names, and version details. This vulnerability poses a significant risk as it does not require authentication, making it easily exploitable by remote attackers.

## Attack Chain

1.  Attacker identifies the AiOPMSD Final 1.0.0 application.
2.  Attacker crafts a malicious SQL payload designed to extract sensitive information.
3.  Attacker sends a GET request to `genre.php` with the crafted SQL payload in the `genre` parameter, for example: `genre.php?genre= ' UNION SELECT username, password FROM users --`.
4.  The application fails to properly sanitize the input, passing the malicious SQL query to the database.
5.  The database executes the injected SQL query, returning sensitive data.
6.  The attacker retrieves the sensitive database information (usernames, database names, version details) from the response.
7.  The attacker uses the extracted information for further malicious activities, such as unauthorized access or data exfiltration.

## Impact

Successful exploitation of the SQL injection vulnerability (CVE-2018-25419) in AiOPMSD Final 1.0.0 allows unauthenticated attackers to extract sensitive database information. This can lead to complete compromise of the application and its data, including usernames, passwords, and other sensitive information stored in the database. The CVSS v3.1 base score for this vulnerability is 8.2, indicating a high severity risk.

## Recommendation

*   Inspect web server logs for GET requests to `genre.php` containing SQL injection attempts (e.g., `UNION SELECT`, `--`, `/*`) using the Sigma rule provided below.
*   Apply input validation and sanitization to the `genre` parameter in `genre.php` to prevent SQL injection attacks.
*   Upgrade to a patched version of AiOPMSD, if available, or implement a web application firewall (WAF) to filter malicious requests.
*   Monitor database logs for anomalous queries that may indicate successful SQL injection attempts.
