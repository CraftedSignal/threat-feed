---
title: itsourcecode Payroll Management System 1.0 SQL Injection Vulnerability
slug: 2026-04-payroll-sql-injection
description: itsourcecode Payroll Management System 1.0 is vulnerable to SQL injection via the ID parameter in /view_employee.php, allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-01T00:16:02Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - payroll-system
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5238
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5238
  - https://github.com/K4ptor/itsourcecode-Payroll-Management-System-V1.0-SQL-Injection2
  - https://vuldb.com/vuln/354389
ioc_counts:
  url: 5
rules:
  - title: Detect SQL Injection Attempt in itsourcecode Payroll Management System
    description: Detects potential SQL injection attempts targeting the /view_employee.php page by looking for SQL keywords in the ID parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via POST Request
    description: Detects SQL Injection Attempts via POST to view_employee.php
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

itsourcecode Payroll Management System 1.0 is vulnerable to SQL injection in the `/view_employee.php` script. This vulnerability, identified as CVE-2026-5238, allows a remote attacker to inject arbitrary SQL commands by manipulating the `ID` parameter. Publicly available exploits exist, increasing the risk of exploitation. Successful exploitation could lead to unauthorized data access, modification, or deletion within the payroll database. This poses a significant threat to organizations using…
