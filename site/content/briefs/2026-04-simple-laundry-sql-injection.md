---
title: code-projects Simple Laundry System 1.0 SQL Injection Vulnerability
slug: 2026-04-simple-laundry-sql-injection
description: A remote SQL Injection vulnerability exists in code-projects Simple Laundry System 1.0 within the /delmemberinfo.php file's userid parameter, potentially allowing attackers to execute arbitrary SQL commands.
date: "2026-04-05T13:17:13Z"
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
cves:
  - id: CVE-2026-5565
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5565
  - https://vuldb.com/vuln/355335
  - https://github.com/mzhnqwqz/cve/issues/1
rules:
  - title: Detect SQL Injection Attempts to delmemberinfo.php
    description: Detects potential SQL injection attempts targeting the /delmemberinfo.php endpoint by looking for common SQL injection syntax in the userid parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages
    description: Detects SQL injection attempts by looking for common database error messages in the web server logs.
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

A security vulnerability, CVE-2026-5565, has been identified in code-projects Simple Laundry System version 1.0. This vulnerability is located within the `/delmemberinfo.php` file, specifically affecting the handling of the `userid` parameter. Successful exploitation of this flaw allows for SQL injection, enabling a remote attacker to potentially manipulate database queries. Publicly available exploits exist, increasing the risk of widespread exploitation targeting vulnerable installations of…
