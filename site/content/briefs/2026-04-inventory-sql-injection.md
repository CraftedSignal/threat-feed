---
title: SQL Injection Vulnerability in code-projects Inventory Management System 1.0
slug: 2026-04-inventory-sql-injection
description: A SQL injection vulnerability exists in code-projects Inventory Management System 1.0 within the Login component, specifically affecting the Username argument, where a remote attacker can manipulate the Username parameter, leading to unauthorized data access or modification.
date: "2026-04-27T01:16:15Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
vendors:
  - code-projects
products:
  - Inventory Management System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7070
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7070
  - https://code-projects.org/
  - https://github.com/MyMySSS/CVE123/blob/main/cve/cve.md
  - https://vuldb.com/submit/798696
  - https://vuldb.com/vuln/359645
  - https://vuldb.com/vuln/359645/cti
rules:
  - title: Detect SQL Injection Attempts in Web Logs
    description: Detects potential SQL injection attempts by searching for common SQL keywords and syntax in HTTP request URIs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via POST Request Body
    description: Detects SQL injection attempts within the body of POST requests, focusing on the 'username' parameter.
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

A SQL injection vulnerability has been identified in code-projects Inventory Management System version 1.0. The vulnerability resides within the Login component and is triggered by manipulating the Username argument. Successful exploitation allows a remote attacker to inject malicious SQL queries, potentially leading to unauthorized access to sensitive data, modification of existing records, or even complete database takeover. The vulnerability, identified as CVE-2026-7070, has a CVSS v3.1…
