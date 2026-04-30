---
title: Zeeways Jobsite CMS SQL Injection Vulnerability (CVE-2019-25636)
slug: 2026-03-zeeways-sqli
description: Zeeways Jobsite CMS is vulnerable to SQL injection, allowing unauthenticated attackers to inject SQL code through the 'id' GET parameter in crafted requests to news_details.php, jobs_details.php, or job_cmp_details.php to extract sensitive database information.
date: "2026-03-24T12:16:04Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - cve-2019-25636
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25636
  - http://www.zeeways.com/jobsite-cms/1/productdetail
  - https://www.exploit-db.com/exploits/46602
  - https://www.vulncheck.com/advisories/zeeways-jobsite-cms-lastest-sql-injection-via-id-parameter
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Zeeways Jobsite CMS SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting Zeeways Jobsite CMS via the 'id' parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Zeeways Jobsite CMS SQL Injection - Exploit DB Pattern
    description: Detects potential SQL injection attempts leveraging exploit DB patterns targeting Zeeways Jobsite CMS via the 'id' parameter
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

Zeeways Jobsite CMS is vulnerable to SQL injection (CVE-2019-25636). This vulnerability allows unauthenticated attackers to inject arbitrary SQL code into database queries via the 'id' GET parameter. The vulnerability affects the news_details.php, jobs_details.php, and job_cmp_details.php files. By sending crafted HTTP requests with malicious 'id' parameter values, attackers can manipulate database queries using techniques like GROUP BY and CASE statements. The initial report was published…
