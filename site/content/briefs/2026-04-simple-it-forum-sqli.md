---
title: Simple IT Discussion Forum SQL Injection Vulnerability
slug: 2026-04-simple-it-forum-sqli
description: CVE-2026-6031 describes a remote SQL injection vulnerability in code-projects Simple IT Discussion Forum 1.0 via manipulation of the 'Category' argument in the /add-category-function.php file.
date: "2026-04-10T08:16:26Z"
severities:
  - high
tags:
  - sql-injection
  - cve-2026-6031
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-6031
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6031
  - https://code-projects.org/
  - https://github.com/GeekShuo/None/issues/2
  - https://vuldb.com/vuln/356607
rules:
  - title: Detect Suspicious Category Parameter in add-category-function.php
    description: Detects potential SQL injection attempts by monitoring the Category parameter in the add-category-function.php file.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempts via GET Request to add-category-function.php
    description: Detects potential SQL injection attempts by monitoring GET requests to the add-category-function.php file with common SQL injection keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been discovered in code-projects Simple IT Discussion Forum version 1.0, identified as CVE-2026-6031. The vulnerability resides in the `/add-category-function.php` file and can be exploited by remotely manipulating the `Category` argument. Successful exploitation allows an attacker to inject malicious SQL queries, potentially leading to unauthorized data access, modification, or deletion. Given the public disclosure of the exploit, this vulnerability poses a…
