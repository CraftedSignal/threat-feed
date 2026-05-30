---
title: AiOPMSD Final 1.0.0 Unauthenticated SQL Injection Vulnerability (CVE-2018-25417)
slug: 2026-05-aiopmsd-sql-injection
description: AiOPMSD Final 1.0.0 is vulnerable to SQL injection (CVE-2018-25417), allowing unauthenticated attackers to execute arbitrary SQL queries via the 'quality' parameter in quality.php, potentially leading to sensitive data exposure.
date: "2026-05-30T16:20:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2018-25417
  - network
products:
  - AiOPMSD Final
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25417
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25417
  - https://aiopmsd.sourceforge.io/
  - https://sourceforge.net/projects/aiopmsd/files/latest/download
  - https://www.exploit-db.com/exploits/45690
  - https://www.vulncheck.com/advisories/aiopmsd-final-sql-injection-via-quality-php
rules:
  - title: Detect AiOPMSD SQL Injection Attempt via quality.php
    description: Detects CVE-2018-25417 exploitation — SQL injection attempt via the quality parameter in quality.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
  - title: Detect AiOPMSD SQL Injection Attempt - String functions
    description: Detects CVE-2018-25417 exploitation — use of string manipulation functions often used to bypass weak SQL injection filters.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
rules_count: 2
---

AiOPMSD Final 1.0.0 is susceptible to an unauthenticated SQL injection vulnerability. This vulnerability allows remote attackers to inject arbitrary SQL code through the `quality` parameter in the `quality.php` script. Successful exploitation could lead to the extraction of sensitive database information, including usernames, database names, and version details. The vulnerability was reported on 2026-05-30 and is identified as CVE-2018-25417. Publicly available exploits exist, increasing the risk of exploitation. This vulnerability poses a significant threat to organizations using the affected software, potentially leading to unauthorized access to sensitive data.

## Attack Chain

1. An unauthenticated attacker identifies an AiOPMSD Final 1.0.0 instance.
2. The attacker crafts a malicious SQL payload.
3. The attacker sends an HTTP GET request to `quality.php`.
4. The attacker injects the SQL payload into the `quality` parameter of the GET request.
5. The web server processes the request and executes the injected SQL query against the database.
6. The database returns the results of the query to the web server.
7. The web server displays the results, potentially including sensitive data.
8. The attacker extracts sensitive data such as usernames, database names, and version details.

## Impact

Successful exploitation of this SQL injection vulnerability could allow an attacker to extract sensitive information from the AiOPMSD Final 1.0.0 database. This information could include user credentials, configuration details, and other sensitive data. The impact could range from unauthorized data access to potential lateral movement within the network if the compromised credentials are reused. Given the publicly available exploits and the ease of exploitation, a successful attack could have severe consequences for organizations using AiOPMSD Final 1.0.0.

## Recommendation

*   Apply any available patches or updates to AiOPMSD Final 1.0.0 to address CVE-2018-25417.
*   Deploy the Sigma rule `Detect AiOPMSD SQL Injection Attempt via quality.php` to your SIEM to identify potential exploitation attempts.
*   Inspect web server logs for suspicious GET requests to `quality.php` containing SQL keywords, to detect exploitation attempts targeting CVE-2018-25417.
*   Monitor network traffic for unusual database activity originating from the web server, which could indicate successful SQL injection and data exfiltration.
