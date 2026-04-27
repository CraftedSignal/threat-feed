---
title: PHPGurukul Daily Expense Tracking System SQL Injection Vulnerability
slug: 2026-04-php-gurukul-sqli
description: A remote SQL injection vulnerability exists in PHPGurukul Daily Expense Tracking System 1.1 within the /register.php file, where manipulation of the email argument allows for arbitrary SQL command execution, with a public exploit available.
date: "2026-04-14T12:00:00Z"
severities:
  - high
tags:
  - sqli
  - cve-2026-6193
  - php
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6193
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6193
  - https://github.com/f1rstb100d/CVE/issues/47
  - https://vuldb.com/vuln/357115
rules:
  - title: Detect Suspicious SQL Injection Attempts in PHPGurukul Registration
    description: Detects potential SQL injection attempts targeting the /register.php endpoint of PHPGurukul Daily Expense Tracking System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PHPGurukul Registration Page Access
    description: Detects access to the PHPGurukul Daily Expense Tracking System registration page, which may indicate reconnaissance or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security flaw has been identified in PHPGurukul Daily Expense Tracking System version 1.1. This vulnerability resides in the `/register.php` file and is triggered by manipulating the `email` argument. Successful exploitation enables remote SQL injection, potentially granting attackers unauthorized access to sensitive database information or allowing them to modify data. This vulnerability, identified as CVE-2026-6193, has a CVSS v3.1 score of 7.3, indicating a high level of severity…
