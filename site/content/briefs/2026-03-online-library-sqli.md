---
title: SourceCodester Online Library Management System SQL Injection Vulnerability (CVE-2026-4624)
slug: 2026-03-online-library-sqli
description: A remote SQL injection vulnerability (CVE-2026-4624) exists in SourceCodester Online Library Management System 1.0 by manipulating the 'searchField' parameter in the /home.php file, potentially allowing attackers to execute arbitrary SQL commands.
date: "2026-03-24T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - cve-2026-4624
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4624
  - https://github.com/WHOAMI-xiaoyu/CVE/blob/main/CVE_6.md
  - https://vuldb.com/?id.352492
rules:
  - title: Detect SQL Injection Attempt via searchField Parameter
    description: Detects potential SQL injection attempts by identifying suspicious characters and SQL keywords within the searchField parameter in requests to /home.php.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious GET Request to home.php
    description: Detects GET requests to home.php which is known to be vulnerable.
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

A SQL injection vulnerability, identified as CVE-2026-4624, affects SourceCodester Online Library Management System version 1.0. The vulnerability resides within the `/home.php` file, specifically in the parameter handler component. By manipulating the `searchField` argument, an attacker can inject malicious SQL code. The attack is remotely exploitable, meaning that an attacker does not need local access to the server. Given the public availability of the exploit, organizations using the…
