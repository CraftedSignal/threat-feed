---
title: SQL Injection Vulnerability in Vehicle Showroom Management System 1.0
slug: 2026-04-vehicle-showroom-sqli
description: A remote attacker can exploit an SQL injection vulnerability (CVE-2026-6165) in code-projects Vehicle Showroom Management System 1.0 by manipulating the ID parameter in /util/Login_check.php, potentially leading to unauthorized data access and modification.
date: "2026-04-13T06:17:51Z"
severities:
  - high
tags:
  - sqli
  - web-application
  - cve-2026-6165
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6165
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6165
  - https://vuldb.com/vuln/357053
rules:
  - title: Detect SQL Injection Attempts in Login_check.php
    description: Detects potential SQL injection attempts by monitoring requests to /util/Login_check.php containing common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via POST Request to Login_check.php
    description: Detects SQL injection attempts targeting Login_check.php via POST requests.
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

CVE-2026-6165 identifies an SQL injection vulnerability within the code-projects Vehicle Showroom Management System version 1.0. The vulnerability resides in the `/util/Login_check.php` file and can be exploited by manipulating the `ID` argument. Successful exploitation allows attackers to inject malicious SQL queries, potentially gaining unauthorized access to sensitive data, modifying database contents, or even executing arbitrary commands on the underlying server. As a publicly available…
