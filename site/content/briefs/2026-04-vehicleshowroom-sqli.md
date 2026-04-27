---
title: code-projects Vehicle Showroom Management System SQL Injection Vulnerability
slug: 2026-04-vehicleshowroom-sqli
description: CVE-2026-6148 is a SQL injection vulnerability in code-projects Vehicle Showroom Management System 1.0, allowing remote attackers to execute arbitrary SQL commands via manipulation of the BRANCH_ID parameter in /util/MonthTotalReportUpdateFunction.php.
date: "2026-04-13T02:16:05Z"
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
  - id: CVE-2026-6148
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6148
  - https://vuldb.com/vuln/357028
rules:
  - title: Detect SQL Injection Attempts via BRANCH_ID Parameter
    description: Detects potential SQL injection attempts targeting the BRANCH_ID parameter in /util/MonthTotalReportUpdateFunction.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Exploitation via Error Messages
    description: Detects potential SQL injection attempts based on common SQL error messages returned by the web server.
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

A SQL injection vulnerability, CVE-2026-6148, has been identified in code-projects Vehicle Showroom Management System version 1.0. The vulnerability resides in the `/util/MonthTotalReportUpdateFunction.php` file and is triggered by manipulating the `BRANCH_ID` argument. The vulnerability allows unauthenticated remote attackers to inject arbitrary SQL commands, potentially leading to data exfiltration, modification, or deletion. Public exploits for this vulnerability are available, increasing…
