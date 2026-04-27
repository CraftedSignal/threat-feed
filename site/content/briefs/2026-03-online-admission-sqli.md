---
title: SourceCodester Online Admission System 1.0 SQL Injection Vulnerability
slug: 2026-03-online-admission-sqli
description: A SQL injection vulnerability in SourceCodester Online Admission System 1.0 allows remote attackers to execute arbitrary SQL commands by manipulating the 'program' argument in the /programmes.php file.
date: "2026-03-24T04:17:14Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4625
  - https://github.com/WHOAMI-xiaoyu/CVE/blob/main/CVE_7.md
  - https://vuldb.com/?ctiid.352493
  - https://vuldb.com/?id.352493
  - https://vuldb.com/?submit.775788
  - https://www.sourcecodester.com/
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect SQL Injection Attempts in SourceCodester Online Admission System
    description: Detects potential SQL injection attempts targeting the /programmes.php endpoint in SourceCodester Online Admission System 1.0
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Potential SQL Injection via POST Request to programmes.php
    description: Detects potential SQL injection attempts via POST requests to the /programmes.php endpoint in SourceCodester Online Admission System 1.0
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

SourceCodester Online Admission System 1.0 is vulnerable to SQL injection. The vulnerability, identified as CVE-2026-4625, resides in the /programmes.php file and can be exploited by manipulating the 'program' argument. An unauthenticated remote attacker can inject malicious SQL queries into the application's database interactions, potentially leading to data exfiltration, modification, or deletion. Publicly available exploit code exists, increasing the risk of widespread exploitation. This…
