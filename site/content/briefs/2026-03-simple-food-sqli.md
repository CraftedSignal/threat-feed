---
title: Simple Food Order System SQL Injection Vulnerability
slug: 2026-03-simple-food-sqli
description: A SQL injection vulnerability (CVE-2026-5019) exists in code-projects Simple Food Order System 1.0, specifically within the all-orders.php file, allowing remote attackers to execute arbitrary SQL commands through manipulation of the 'Status' argument.
date: "2026-03-29T00:16:13Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-5019
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5019
  - https://vuldb.com/vuln/353904
rules:
  - title: Detect Suspicious SQL Injection Attempts
    description: Detects potential SQL injection attempts in HTTP requests based on common SQL keywords
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious SQL Injection via POST Request
    description: Detects potential SQL injection attempts in HTTP POST requests based on common SQL keywords
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

A critical security vulnerability, identified as CVE-2026-5019, has been discovered in code-projects Simple Food Order System version 1.0. The vulnerability resides within the `all-orders.php` file, a component responsible for handling parameters related to order status. A remote attacker can exploit this weakness by injecting malicious SQL code into the `Status` argument. The vulnerability has been publicly disclosed, increasing the risk of exploitation. Simple Food Order System 1.0 is…
