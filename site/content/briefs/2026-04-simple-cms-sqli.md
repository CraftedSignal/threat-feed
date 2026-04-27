---
title: SQL Injection Vulnerability in Simple Content Management System 1.0
slug: 2026-04-simple-cms-sqli
description: A remote SQL injection vulnerability exists in code-projects Simple Content Management System 1.0, specifically affecting the /web/admin/login.php file where manipulation of the 'User' argument allows unauthenticated attackers to execute arbitrary SQL queries.
date: "2026-04-13T15:17:49Z"
severities:
  - high
tags:
  - sqli
  - web-application
  - cve-2026-6182
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6182
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6182
  - https://code-projects.org/
  - https://github.com/Xmyronn/simple-cms-sqli-login-bypass-CVE-HUNT-
  - https://vuldb.com/submit/797263
  - https://vuldb.com/vuln/357105
  - https://vuldb.com/vuln/357105/cti
ioc_counts:
  url: 5
rules:
  - title: Detect SQL Injection Attempts in Simple CMS Login
    description: Detects potential SQL injection attempts in requests to the /web/admin/login.php endpoint by looking for common SQL keywords in the User parameter.
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
  - title: Detect Simple CMS SQL Injection Errors
    description: Detects potential SQL injection errors by analyzing web server logs for specific error messages related to database interactions in the /web/admin/login.php endpoint.
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

A SQL injection vulnerability has been identified in code-projects Simple Content Management System (CMS) version 1.0. The vulnerability resides in the `/web/admin/login.php` file and stems from improper sanitization of user-supplied input within the `User` argument. An unauthenticated, remote attacker can exploit this vulnerability to inject arbitrary SQL commands, potentially leading to unauthorized data access, modification, or deletion. Publicly available exploits exist, increasing the risk…
