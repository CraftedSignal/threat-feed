---
title: Meeplace Business Review Script SQL Injection Vulnerability (CVE-2019-25638)
slug: 2026-03-meeplace-sql-injection
description: Meeplace Business Review Script is vulnerable to SQL injection via the 'id' parameter in the addclick.php endpoint, allowing unauthenticated attackers to execute arbitrary SQL queries and potentially extract sensitive database information or cause a denial of service.
date: "2026-03-24T12:16:04Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - web-application
  - cve-2019-25638
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25638
  - https://www.exploit-db.com/exploits/46592
  - https://www.vulncheck.com/advisories/meeplace-business-review-script-lastest-sql-injection-via-addclick-php
rules:
  - title: Detect Meeplace SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the addclick.php endpoint in Meeplace Business Review Script.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Meeplace addclick.php Access
    description: Detects access to the addclick.php endpoint which may indicate a vulnerability scan or exploit attempt.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Meeplace Business Review Script is susceptible to an SQL injection vulnerability (CVE-2019-25638) affecting the addclick.php endpoint. Unauthenticated attackers can exploit this vulnerability by injecting malicious SQL code through the 'id' parameter in GET requests. This can lead to the execution of arbitrary SQL queries, potentially enabling attackers to retrieve sensitive database information or trigger a denial-of-service condition. The vulnerability was published on 2026-03-24 and poses a…
