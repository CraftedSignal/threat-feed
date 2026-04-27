---
title: Zeeways Matrimony CMS Unauthenticated SQL Injection Vulnerability
slug: 2026-03-zeeways-sql-injection
description: Zeeways Matrimony CMS is vulnerable to SQL injection via the profile_list endpoint, where an unauthenticated attacker can inject SQL code via the up_cast, s_mother, and s_religion parameters, potentially allowing them to extract sensitive information.
date: "2026-03-24T12:16:04Z"
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - matrimony-cms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25635
  - http://www.zeeways.com/matrimony-cms/4/productdetail
  - https://www.exploit-db.com/exploits/46603
  - https://www.vulncheck.com/advisories/zeeways-matrimony-cms-lastest-sql-injection-via-profile-list
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Detect SQL Injection Attempts in Zeeways Matrimony CMS via profile_list
    description: Detects potential SQL injection attempts targeting the profile_list endpoint in Zeeways Matrimony CMS through suspicious parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection - Error Based
    description: Detects potential SQL injection attempts based on common error messages in web server logs.
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

Zeeways Matrimony CMS is susceptible to SQL injection vulnerabilities affecting the profile_list endpoint. This vulnerability allows unauthenticated attackers to inject malicious SQL code through the `up_cast`, `s_mother`, and `s_religion` parameters. Successful exploitation could lead to unauthorized access to sensitive data within the database. The vulnerability was reported in CVE-2019-25635. The vulnerable software is Zeeways Matrimony CMS, and it's crucial for organizations using this CMS…
