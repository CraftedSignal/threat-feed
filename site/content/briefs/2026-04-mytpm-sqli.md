---
title: MyT-PM 1.5.1 SQL Injection Vulnerability
slug: 2026-04-mytpm-sqli
description: MyT-PM 1.5.1 is vulnerable to SQL injection, allowing authenticated attackers to execute arbitrary SQL queries via the Charge[group_total] parameter.
date: "2026-04-12T13:16:34Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2019-25713
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25713
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25713
  - https://manageyourteam.net/
  - https://sourceforge.net/projects/myt/
  - https://www.exploit-db.com/exploits/46084
  - https://www.vulncheck.com/advisories/myt-pm-sql-injection-via-charge-group-total-parameter
ioc_counts:
  url: 4
rules:
  - title: Detect SQL Injection Attempts in MyT-PM Charge Endpoint
    description: Detects potential SQL injection attempts targeting the /charge/admin endpoint in MyT-PM through the Charge[group_total] parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1212
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection UNION SELECT
    description: Detects UNION SELECT strings in web requests, indicating possible SQL injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1212
    data_sources:
      - webserver
      - linux
rules_count: 2
---

MyT-PM 1.5.1 is susceptible to an SQL injection vulnerability (CVE-2019-25713) that enables authenticated attackers to execute arbitrary SQL queries. This vulnerability exists due to insufficient input sanitization of the `Charge[group_total]` parameter. By sending specially crafted POST requests to the `/charge/admin` endpoint, an attacker can inject malicious SQL code, potentially leading to sensitive data extraction, data manipulation, or other unauthorized actions. This vulnerability poses…
