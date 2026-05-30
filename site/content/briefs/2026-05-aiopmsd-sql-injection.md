---
title: AiOPMSD Final 1.0.0 Unauthenticated SQL Injection Vulnerability (CVE-2018-25415)
slug: 2026-05-aiopmsd-sql-injection
description: AiOPMSD Final 1.0.0 is vulnerable to SQL injection (CVE-2018-25415), allowing unauthenticated attackers to execute arbitrary SQL queries by injecting malicious code through the director parameter in GET requests, potentially leading to sensitive data extraction.
date: "2026-05-30T16:19:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2018-25415
  - web-application
products:
  - AiOPMSD Final 1.0.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25415
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25415
  - https://aiopmsd.sourceforge.io/
  - https://sourceforge.net/projects/aiopmsd/files/latest/download
  - https://www.exploit-db.com/exploits/45690
  - https://www.vulncheck.com/advisories/aiopmsd-final-sql-injection-via-director-parameter
rules:
  - title: Detect CVE-2018-25415 Exploitation — SQL Injection via director.php
    description: Detects CVE-2018-25415 exploitation — HTTP GET request to director.php with suspicious SQL syntax in the director parameter indicating a SQL injection attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious SQL Injection Attempts via director.php
    description: Detects HTTP GET requests to director.php containing potential SQL injection attempts based on common SQL keywords and syntax.
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

AiOPMSD Final 1.0.0 is susceptible to SQL injection, as detailed in CVE-2018-25415. Unauthenticated attackers can exploit this vulnerability by injecting malicious SQL code through the `director` parameter in HTTP GET requests to the `director.php` script. The vulnerability allows attackers to execute arbitrary SQL queries, potentially leading to the extraction of sensitive database information. Successful exploitation could allow attackers to retrieve usernames, database names, version details, and other sensitive data stored within the application's database. This vulnerability poses a significant risk to organizations using AiOPMSD Final 1.0.0, as it can lead to data breaches and unauthorized access to confidential information.

## Attack Chain

1. An unauthenticated attacker identifies an AiOPMSD Final 1.0.0 instance.
2. The attacker crafts a malicious SQL payload designed to extract sensitive information.
3. The attacker constructs a GET request targeting `director.php`, embedding the SQL payload within the `director` parameter (e.g., `director.php?director=malicious_sql`).
4. The web server processes the request and passes the `director` parameter to the vulnerable SQL query.
5. The malicious SQL payload is executed against the database.
6. The database executes the attacker's SQL query, potentially leaking sensitive data.
7. The extracted data, such as usernames, database names, or version information, is returned in the HTTP response.
8. The attacker parses the HTTP response to retrieve the extracted sensitive information, gaining unauthorized access to confidential data.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25415) in AiOPMSD Final 1.0.0 can result in the disclosure of sensitive information, including usernames, database names, and version details. An attacker could use this information to gain further access to the system, escalate privileges, or perform other malicious activities. Given a CVSS v3.1 score of 8.2, this vulnerability poses a high risk.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2018-25415 Exploitation` to detect potential exploitation attempts against the `director.php` endpoint.
*   Inspect web server logs for HTTP GET requests to `director.php` containing suspicious SQL syntax within the `director` parameter, as covered by the `Detect Suspicious SQL Injection Attempts via director.php` Sigma rule.
*   Implement input validation and sanitization on the `director` parameter to prevent SQL injection, according to secure coding practices.
