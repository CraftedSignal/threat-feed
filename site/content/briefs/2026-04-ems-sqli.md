---
title: code-projects Employee Management System SQL Injection Vulnerability (CVE-2026-7063)
slug: 2026-04-ems-sqli
description: CVE-2026-7063 is a SQL Injection vulnerability in code-projects Employee Management System 1.0 via the 'pwd' parameter in /370project/process/eprocess.php, enabling remote attackers to execute arbitrary SQL commands.
date: "2026-04-26T23:16:21Z"
severities:
  - high
tags:
  - sqli
  - cve-2026-7063
  - web-application
vendors:
  - code-projects
products:
  - Employee Management System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7063
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7063
  - https://vuldb.com/vuln/359638
  - https://github.com/ahmadmarz10-hub/CVEsMarz/blob/main/SQL%20Injection%20in%20Employee%20Management%20System%20PHP%20mailuid%20Parameter.md
rules:
  - title: Detect SQL Injection Attempt via pwd Parameter
    description: Detects potential SQL injection attempts by monitoring POST requests to the /370project/process/eprocess.php endpoint with suspicious SQL syntax in the pwd parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via pwd parameter in web logs
    description: This rule detects potential SQL injection attempts by looking for specific SQL keywords and syntax within the 'pwd' parameter in web server logs.
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

A SQL injection vulnerability, identified as CVE-2026-7063, has been discovered in code-projects Employee Management System version 1.0. The vulnerability resides within the `/370project/process/eprocess.php` file, specifically affecting the `pwd` argument. Successful exploitation allows a remote attacker to inject and execute arbitrary SQL commands against the application's database. Given that the exploit is publicly available, organizations using this system are at immediate risk of…
