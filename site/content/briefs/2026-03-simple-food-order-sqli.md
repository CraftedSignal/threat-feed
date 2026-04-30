---
title: code-projects Simple Food Order System SQL Injection Vulnerability (CVE-2026-5017)
slug: 2026-03-simple-food-order-sqli
description: CVE-2026-5017 is a SQL injection vulnerability in code-projects Simple Food Order System 1.0, allowing remote attackers to execute arbitrary SQL commands by manipulating the 'Status' parameter in the `/all-tickets.php` file.
date: "2026-03-28T23:16:43Z"
severities:
  - high
type: advisory
types:
  - advisory
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
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5017
  - https://vuldb.com/vuln/353902
  - https://github.com/6Justdododo6/CVE/issues/15
rules:
  - title: Detect SQL Injection Attempt in Simple Food Order System
    description: Detects potential SQL injection attempts targeting the /all-tickets.php endpoint by monitoring for suspicious keywords in the query string.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt via POST Request
    description: Detects potential SQL injection attempts via POST request parameters.
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

A SQL injection vulnerability, identified as CVE-2026-5017, affects code-projects Simple Food Order System version 1.0. This vulnerability resides within the `/all-tickets.php` file, specifically in how the application handles the 'Status' parameter. A remote attacker can exploit this flaw by crafting malicious SQL queries via the 'Status' argument, potentially leading to unauthorized data access, modification, or complete system compromise. The vulnerability has been publicly disclosed…
