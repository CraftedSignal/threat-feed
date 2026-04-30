---
title: YunaiV yudao-cloud SQL Injection Vulnerability
slug: 2026-03-yudao-sql-injection
description: A remote SQL injection vulnerability (CVE-2026-5147) exists in YunaiV yudao-cloud up to version 2026.01 via the Website argument in the /admin-api/system/tenant/get-by-website endpoint, allowing unauthenticated attackers to potentially execute arbitrary SQL queries.
date: "2026-03-30T19:16:27Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-5147
  - sql-injection
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5147
  - https://github.com/NarcherAlter/Security_Note/blob/main/Vulnerability_Discovery/yudaoCloudv2026.01.md
  - https://vuldb.com/vuln/354181
rules:
  - title: Detect SQL Injection Attempts in yudao-cloud Website Parameter
    description: Detects potential SQL injection attempts targeting the Website parameter in the /admin-api/system/tenant/get-by-website endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Database Queries from yudao-cloud
    description: Detects suspicious database queries originating from the yudao-cloud application, potentially indicating SQL injection exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - database
      - mysql
rules_count: 2
---

A security flaw, identified as CVE-2026-5147, has been discovered in YunaiV yudao-cloud software, specifically versions up to 2026.01. The vulnerability resides in the `/admin-api/system/tenant/get-by-website` endpoint, where manipulation of the `Website` argument can lead to SQL injection. This allows for potential remote exploitation without requiring authentication. The vulnerability was reported to the vendor, but no response or patch has been provided. Publicly available exploit code…
