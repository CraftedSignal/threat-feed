---
title: PHPGurukul News Portal Project SQL Injection Vulnerability (CVE-2026-5837)
slug: 2026-04-phpgurukul-sql-injection
description: PHPGurukul News Portal Project version 4.1 is vulnerable to SQL injection via the Comment parameter in /news-details.php, potentially allowing remote attackers to execute arbitrary SQL queries.
date: "2026-04-09T04:17:23Z"
severities:
  - high
exploited: true
tags:
  - sql-injection
  - web-application
  - php
  - CVE-2026-5837
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5837
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5837
  - https://github.com/f1rstb100d/CVE/issues/25
  - https://phpgurukul.com/
  - https://vuldb.com/submit/789775
  - https://vuldb.com/vuln/356293
  - https://vuldb.com/vuln/356293/cti
rules:
  - title: Detecting SQL Injection in PHPGurukul News Portal
    description: Detects potential SQL injection attempts in PHPGurukul News Portal by looking for suspicious characters in the URI query string.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting Potential SQL Injection via Comment Parameter
    description: Detects potential SQL Injection attacks by looking for base64 encoded strings in the Comment parameter
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

CVE-2026-5837 describes a SQL injection vulnerability affecting PHPGurukul News Portal Project version 4.1. The vulnerability resides in the `/news-details.php` file and is triggered by manipulating the `Comment` argument.  Successful exploitation allows remote attackers to inject arbitrary SQL commands into the application's database queries. The vulnerability has a CVSS v3.1 score of 7.3, indicating a high severity. Publicly available exploits exist, increasing the risk of active…
