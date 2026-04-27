---
title: ResourceSpace 8.6 SQL Injection Vulnerability
slug: 2026-04-resourcespace-sqli
description: ResourceSpace 8.6 is vulnerable to SQL injection, allowing unauthenticated attackers to execute arbitrary SQL queries via the 'ref' parameter in GET requests to the watched_searches.php endpoint, leading to sensitive data extraction.
date: "2026-04-05T21:16:43Z"
severities:
  - high
tags:
  - sqli
  - cve-2019-25662
  - resourcespace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25662
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25662
  - https://www.exploit-db.com/exploits/46308
  - https://www.resourcespace.com/
  - https://www.resourcespace.com/get
  - https://www.vulncheck.com/advisories/resourcespace-sql-injection-via-watched-searches-php
rules:
  - title: Detect ResourceSpace SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the /watched_searches.php endpoint in ResourceSpace by monitoring for suspicious characters and SQL keywords in the 'ref' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ResourceSpace SQL Injection Attempt - Error Based
    description: Detects potential error-based SQL injection attempts against ResourceSpace by monitoring for specific error-inducing payloads in the 'ref' parameter of requests to /watched_searches.php.
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

ResourceSpace 8.6 is susceptible to a critical SQL injection vulnerability (CVE-2019-25662) that allows unauthenticated attackers to execute arbitrary SQL queries. The vulnerability is located within the watched_searches.php endpoint and is triggered through the 'ref' parameter in GET requests. By injecting malicious SQL code into this parameter, attackers can bypass authentication and directly interact with the database, potentially extracting sensitive information such as usernames and…
