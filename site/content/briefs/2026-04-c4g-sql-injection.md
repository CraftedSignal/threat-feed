---
title: C4G Basic Laboratory Information System 3.4 SQL Injection Vulnerability
slug: 2026-04-c4g-sql-injection
description: C4G Basic Laboratory Information System 3.4 is vulnerable to SQL injection, allowing unauthenticated attackers to execute arbitrary SQL commands via the 'site' parameter in GET requests to the users_select.php endpoint, potentially leading to sensitive data extraction.
date: "2026-04-05T21:16:45Z"
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - cve-2019-25678
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25678
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25678
  - https://www.exploit-db.com/exploits/46438
  - https://www.vulncheck.com/advisories/c4g-blis-sql-injection-via-users-select-php
rules:
  - title: Detect SQL Injection Attempt in C4G Basic LIS
    description: Detects potential SQL injection attempts targeting the users_select.php endpoint of C4G Basic Laboratory Information System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via GET Request to users_select.php
    description: This rule detects potential SQL injection attacks by monitoring GET requests to 'users_select.php' with suspicious characters in the query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

C4G Basic Laboratory Information System version 3.4 is susceptible to SQL injection vulnerabilities. The vulnerability allows unauthenticated attackers to inject malicious SQL code through the `site` parameter in HTTP GET requests targeting the `users_select.php` endpoint. Successful exploitation could grant attackers unauthorized access to sensitive data stored within the system's database, including confidential patient records and system credentials. This vulnerability poses a significant…
