---
title: SQL Injection Vulnerability in Simple Food Order System 1.0
slug: 2026-03-simple-food-sqli
description: A SQL injection vulnerability exists in code-projects Simple Food Order System 1.0 within the register-router.php file, where manipulation of the Name argument can lead to remote code execution.
date: "2026-03-28T23:16:44Z"
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
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5018
  - https://vuldb.com/vuln/353903
rules:
  - title: Detect Suspicious SQL Injection Attempts
    description: Detects potential SQL injection attempts in HTTP requests based on common SQL syntax.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection in register-router.php
    description: Detects SQL injection attempts specifically targeting the register-router.php file.
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

A SQL injection vulnerability has been identified in the code-projects Simple Food Order System version 1.0. The vulnerability resides within the `register-router.php` file, specifically affecting the handling of the 'Name' argument. An attacker can remotely exploit this weakness by manipulating the 'Name' parameter, leading to arbitrary SQL execution. Given the public availability of exploit code, the risk of active exploitation is elevated. This vulnerability is particularly concerning as it…
