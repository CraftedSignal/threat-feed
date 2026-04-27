---
title: CodePanda Source canteen_management_system SQL Injection Vulnerability
slug: 2026-04-canteen-sql-injection
description: A SQL injection vulnerability exists in CodePanda Source canteen_management_system version 1.0 within the /api/login.php file by manipulating the Username argument, allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-27T01:16:16Z"
severities:
  - high
tags:
  - sql-injection
  - cve-2026-7072
  - web-application
vendors:
  - CodePanda Source
products:
  - canteen_management_system 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7072
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7072
  - https://github.com/redshadowword-cell/CVE/issues/2
  - https://vuldb.com/submit/799482
  - https://vuldb.com/vuln/359647
  - https://vuldb.com/vuln/359647/cti
rules:
  - title: Detect SQL Injection Attempts in canteen_management_system Login
    description: Detects potential SQL injection attempts targeting the /api/login.php endpoint by looking for common SQL syntax in the Username parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 1
---

A SQL injection vulnerability has been identified in CodePanda Source canteen_management_system version 1.0. The vulnerability resides in the `/api/login.php` file and is triggered by manipulating the `Username` argument. This allows a remote attacker to inject arbitrary SQL commands into the application's database queries. Public exploits are available, increasing the risk of exploitation. Successful exploitation could lead to unauthorized data access, modification, or deletion, potentially…
