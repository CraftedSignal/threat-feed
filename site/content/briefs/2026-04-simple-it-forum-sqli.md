---
title: Simple IT Discussion Forum SQL Injection Vulnerability (CVE-2026-6004)
slug: 2026-04-simple-it-forum-sqli
description: CVE-2026-6004 is a SQL injection vulnerability in code-projects Simple IT Discussion Forum 1.0's /delete-category.php, allowing remote attackers to execute arbitrary SQL commands by manipulating the cat_id parameter.
date: "2026-04-10T03:19:12Z"
severities:
  - high
tags:
  - sqli
  - cve-2026-6004
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6004
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6004
  - https://vuldb.com/vuln/356560
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious URI Access to delete-category.php
    description: Detects suspicious access to the /delete-category.php file which is vulnerable to SQL injection
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempts via URI
    description: Detects potential SQL injection attempts in URI parameters.
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

A SQL injection vulnerability, CVE-2026-6004, has been identified in code-projects Simple IT Discussion Forum version 1.0. The vulnerability resides within the `/delete-category.php` file and stems from improper handling of the `cat_id` argument. A remote attacker can exploit this flaw to inject malicious SQL code, potentially leading to unauthorized data access, modification, or deletion. The vulnerability was published on April 9, 2026, and a public exploit is available, increasing the risk…
