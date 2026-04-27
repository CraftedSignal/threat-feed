---
title: Vehicle Showroom Management System SQL Injection Vulnerability (CVE-2026-6152)
slug: 2026-04-vehicle-showroom-sql-injection
description: A remote SQL injection vulnerability exists in code-projects Vehicle Showroom Management System 1.0 due to improper handling of the STAFF_ID parameter in /util/StaffAddingFunction.php, potentially allowing attackers to execute arbitrary SQL commands.
date: "2026-04-13T03:16:03Z"
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
  - id: CVE-2026-6152
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6152
  - https://code-projects.org/
  - https://github.com/zheng-lv/CVE-/issues/3
  - https://vuldb.com/vuln/357032
rules:
  - title: Detect SQL Injection Attempt in Vehicle Showroom Management System
    description: Detects potential SQL injection attempts targeting the /util/StaffAddingFunction.php file in Vehicle Showroom Management System via the STAFF_ID parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Exploitation via GitHub Public Exploit URL
    description: Detects requests coming from GitHub to the vehicle showroom exploit code.
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

CVE-2026-6152 details a critical SQL injection vulnerability within version 1.0 of the code-projects Vehicle Showroom Management System. The flaw resides in the `/util/StaffAddingFunction.php` file and is triggered by manipulating the `STAFF_ID` parameter. Publicly disclosed exploits exist, meaning unauthenticated remote attackers can leverage this vulnerability to inject malicious SQL queries into the application's database. Successful exploitation could lead to unauthorized data access…
