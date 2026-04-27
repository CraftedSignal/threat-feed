---
title: News Website Script 2.0.5 SQL Injection Vulnerability
slug: 2026-04-news-website-sqli
description: News Website Script 2.0.5 contains an SQL injection vulnerability (CVE-2019-25668) allowing unauthenticated attackers to extract sensitive information by injecting SQL code through the news ID parameter in GET requests.
date: "2026-04-05T21:16:44Z"
severities:
  - high
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

News Website Script version 2.0.5 is susceptible to SQL injection, as identified by CVE-2019-25668. This vulnerability allows unauthenticated remote attackers to manipulate database queries by injecting malicious SQL code via the 'news ID' parameter. Successful exploitation grants attackers the ability to extract sensitive information directly from the application database. The vulnerability lies within the index.php/show/news/ endpoint and can be exploited via simple HTTP GET requests, making…
