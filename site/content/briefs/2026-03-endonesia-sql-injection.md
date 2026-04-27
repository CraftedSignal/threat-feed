---
title: eNdonesia Portal v8.7 SQL Injection Vulnerability
slug: 2026-03-endonesia-sql-injection
description: eNdonesia Portal v8.7 is vulnerable to SQL injection allowing unauthenticated attackers to execute arbitrary SQL queries via the bid parameter in banners.php, potentially leading to sensitive data extraction.
date: "2026-03-24T12:16:06Z"
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - cve-2019-25643
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25643
  - https://www.exploit-db.com/exploits/46559
  - https://www.vulncheck.com/advisories/endonesia-portal-sql-injection-via-banners-php
rules:
  - title: Detecting eNdonesia banners.php SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the banners.php endpoint in eNdonesia Portal v8.7
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting eNdonesia banners.php SQL Injection via POST
    description: Detects potential SQL injection attempts targeting the banners.php endpoint in eNdonesia Portal v8.7 via POST requests
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

eNdonesia Portal v8.7 is susceptible to SQL injection vulnerabilities. Unauthenticated attackers can exploit this flaw by injecting malicious SQL code through the `bid` parameter in the `banners.php` script. The vulnerability allows attackers to execute arbitrary SQL queries against the application's database. Successful exploitation could lead to the unauthorized extraction of sensitive information, including database schema details from `INFORMATION_SCHEMA` tables. This vulnerability…
