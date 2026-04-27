---
title: SQL Injection Vulnerability in Easy Blog Site 1.0
slug: 2026-04-easy-blog-sql-injection
description: A SQL injection vulnerability exists in code-projects Easy Blog Site 1.0 within the login.php file, exploitable remotely by manipulating the username/password parameters, potentially leading to unauthorized database access.
date: "2026-04-06T11:17:03Z"
severities:
  - high
tags:
  - sqlinjection
  - cve-2026-5646
  - webapplication
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5646
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5646
  - https://code-projects.org/
  - https://github.com/MyMySSS/cve/blob/main/cve.md
  - https://vuldb.com/submit/786150
  - https://vuldb.com/vuln/355434
  - https://vuldb.com/vuln/355434/cti
rules:
  - title: Detect SQL Injection Attempts in Easy Blog Site Login
    description: Detects potential SQL injection attempts targeting the login.php file of Easy Blog Site 1.0 based on SQL syntax in POST request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Publicly Available Exploit Pattern for Easy Blog Site
    description: Detects requests resembling publicly available exploit code targeting Easy Blog Site 1.0 based on observed strings.
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

A SQL injection vulnerability has been identified in code-projects Easy Blog Site 1.0, specifically affecting the login.php file. This vulnerability allows a remote attacker to inject malicious SQL code through the username and password parameters. The vulnerability, identified as CVE-2026-5646, stems from improper sanitization of user-supplied input, potentially allowing attackers to bypass authentication or extract sensitive data from the application's database. The exploit has been publicly…
