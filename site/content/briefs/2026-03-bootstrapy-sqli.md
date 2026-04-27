---
title: Bootstrapy CMS Unauthenticated SQL Injection Vulnerabilities
slug: 2026-03-bootstrapy-sqli
description: Bootstrapy CMS contains multiple SQL injection vulnerabilities that allow unauthenticated attackers to execute arbitrary SQL queries by injecting malicious code through POST parameters to extract sensitive database information or cause denial of service.
date: "2026-03-24T12:16:06Z"
severities:
  - critical
tags:
  - sql-injection
  - bootstrapy-cms
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25642
  - https://www.exploit-db.com/exploits/46590
  - https://www.vulncheck.com/advisories/bootstrapy-cms-lastest-multiple-sql-injection-via-forum-and-contact-modules
ioc_counts:
  url: 3
rules:
  - title: Detect SQL Injection Attempt in Bootstrapy CMS forum-thread.php
    description: Detects potential SQL injection attempts in Bootstrapy CMS by monitoring POST requests to forum-thread.php with suspicious SQL syntax in the thread_id parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt in Bootstrapy CMS contact-submit.php
    description: Detects potential SQL injection attempts in Bootstrapy CMS by monitoring POST requests to contact-submit.php with suspicious SQL syntax in the subject parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt in Bootstrapy CMS post-new-submit.php
    description: Detects potential SQL injection attempts in Bootstrapy CMS by monitoring POST requests to post-new-submit.php with suspicious SQL syntax in the post-id parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Bootstrapy CMS is vulnerable to multiple SQL injection vulnerabilities (CVE-2019-25642). These vulnerabilities allow unauthenticated attackers to execute arbitrary SQL queries. The attack vector involves injecting malicious SQL code via POST parameters in specific PHP files: `forum-thread.php`, `contact-submit.php`, and `post-new-submit.php`. Successful exploitation can lead to sensitive database information disclosure or a denial-of-service condition. The identified vulnerabilities exist in…
