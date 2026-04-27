---
title: manikandan580 School-management-system SQL Injection Vulnerability
slug: 2026-04-school-management-sqli
description: A time-based blind SQL injection vulnerability in manikandan580 School-management-system 1.0 allows unauthenticated attackers to potentially execute arbitrary SQL queries and gain unauthorized access to sensitive information.
date: "2026-04-15T12:00:00Z"
severities:
  - critical
tags:
  - sqli
  - cve-2025-65135
  - school-management-system
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-65135
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-65135
  - https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2025-65135
rules:
  - title: Detect SQL Injection Attempts via POST to between-date-reprtsdetails.php
    description: Detects potential SQL injection attempts targeting the fromdate parameter in the between-date-reprtsdetails.php script.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages in Web Server Logs
    description: Detects SQL injection attempts by identifying common database error messages in web server logs.
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

A critical time-based blind SQL injection vulnerability, identified as CVE-2025-65135, affects version 1.0 of the manikandan580 School-management-system. This vulnerability resides in the `/studentms/admin/between-date-reprtsdetails.php` script and is exploitable through the `fromdate` POST parameter. Given the nature of the vulnerability, attackers can potentially bypass authentication and execute arbitrary SQL queries on the back-end database. Successful exploitation could lead to…
