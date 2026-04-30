---
title: code-projects Accounting System 1.0 SQL Injection Vulnerability (CVE-2026-5034)
slug: 2026-03-code-projects-sqli
description: A remote SQL injection vulnerability exists in code-projects Accounting System 1.0 via manipulation of the 'cos_id' parameter in '/edit_costumer.php', potentially allowing unauthorized database access.
date: "2026-03-29T06:16:12Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sqli
  - cve-2026-5034
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5034
  - https://code-projects.org/
  - https://github.com/Xu-Zhihan/CVE/issues/7
  - https://vuldb.com/vuln/353960
  - https://vuldb.com/vuln/353960/cti
rules:
  - title: Detect SQL Injection Attempts in code-projects Accounting System
    description: Detects potential SQL injection attacks targeting the cos_id parameter in /edit_costumer.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect code-projects Accounting System /edit_costumer.php Access
    description: Detects access to the /edit_costumer.php page, which should be monitored for suspicious activity.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-5034, has been discovered in code-projects Accounting System version 1.0. The vulnerability resides in the `/edit_costumer.php` file within the Parameter Handler component. Attackers can remotely exploit this vulnerability by manipulating the `cos_id` argument. Publicly available exploit code exists, increasing the risk of widespread exploitation. This vulnerability allows unauthenticated remote attackers to potentially execute arbitrary SQL…
