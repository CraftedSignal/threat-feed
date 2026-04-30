---
title: News Website Script 2.0.5 SQL Injection Vulnerability
slug: 2026-04-news-website-sqli
description: News Website Script 2.0.5 contains an SQL injection vulnerability (CVE-2019-25668) allowing unauthenticated attackers to extract sensitive information by injecting SQL code through the news ID parameter in GET requests.
date: "2026-04-05T21:16:44Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sqli
  - cve-2019-25668
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25668
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25668
  - https://www.exploit-db.com/exploits/46456
  - https://www.vulncheck.com/advisories/news-website-script-sql-injection-via-index-php
rules:
  - title: Detect SQL Injection Attempts in News Website Script
    description: Detects potential SQL injection attempts targeting the index.php/show/news/ endpoint in News Website Script.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Error Messages Indicating Injection
    description: Detects common SQL error messages returned by the server, indicating potential SQL injection.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

News Website Script version 2.0.5 is susceptible to SQL injection, as identified by CVE-2019-25668. This vulnerability allows unauthenticated remote attackers to manipulate database queries by injecting malicious SQL code via the 'news ID' parameter. Successful exploitation grants attackers the ability to extract sensitive information directly from the application database. The vulnerability lies within the index.php/show/news/ endpoint and can be exploited via simple HTTP GET requests, making it easily accessible. The risk to organizations using this vulnerable software is significant, potentially leading to data breaches and unauthorized access to confidential information.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable instance of News Website Script 2.0.5.
2. The attacker crafts a malicious HTTP GET request targeting the `/index.php/show/news/` endpoint.
3. The crafted GET request includes a `news` parameter containing a SQL injection payload.
4. The web server receives the malicious request and passes the SQL injection payload to the application's database query.
5. The database executes the injected SQL code without proper sanitization.
6. The attacker extracts sensitive data from the database, such as user credentials, financial information, or proprietary data.
7. The attacker may use the extracted information to further compromise the system or network.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2019-25668) can lead to the complete compromise of the affected News Website Script 2.0.5 database. The impact includes unauthorized access to sensitive data, potential data breaches, and the ability for attackers to modify or delete data. The number of potential victims is dependent on the install base of the vulnerable software.

## Recommendation

*   Apply available patches or upgrade to a secure version of News Website Script to remediate CVE-2019-25668.
*   Deploy the Sigma rule provided in this brief to detect exploitation attempts targeting the vulnerable endpoint `index.php/show/news/`.
*   Implement input validation and sanitization for all user-supplied input to prevent SQL injection attacks.
