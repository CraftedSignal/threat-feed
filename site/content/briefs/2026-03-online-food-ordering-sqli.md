---
title: code-projects Online Food Ordering System SQL Injection Vulnerability (CVE-2026-4844)
slug: 2026-03-online-food-ordering-sqli
description: CVE-2026-4844 describes a SQL injection vulnerability in the Admin Login Module of code-projects Online Food Ordering System 1.0, which can be exploited remotely by manipulating the Username argument in the /admin.php file.
date: "2026-03-26T05:16:41Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - web-application
  - cve-2026-4844
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4844
  - https://code-projects.org/
  - https://gist.github.com/HxH404/8e5bd42c0f968a92a23edc5e7b879955
  - https://vuldb.com/?ctiid.353149
  - https://vuldb.com/?id.353149
  - https://vuldb.com/?submit.776137
rules:
  - title: Detect SQL Injection in Online Food Ordering System Login
    description: Detects potential SQL injection attempts in the Username parameter of the /admin.php login page of code-projects Online Food Ordering System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - sql_injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Database Errors from Web Server
    description: Detects database error messages returned by the web server, which may indicate a successful SQL injection.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - sql_injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-4844, affects the code-projects Online Food Ordering System version 1.0. Specifically, the vulnerability resides within the Admin Login Module and is triggered by manipulating the Username argument when processing the `/admin.php` file. This allows a remote attacker to inject arbitrary SQL commands. Public exploits are available, increasing the risk of exploitation. Successful exploitation can lead to unauthorized access to the database…
