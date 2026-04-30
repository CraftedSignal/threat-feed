---
title: SQL Injection Vulnerability in code-projects Accounting System 1.0 (CVE-2026-5150)
slug: 2026-03-code-projects-sql-injection
description: A remote SQL injection vulnerability (CVE-2026-5150) exists in code-projects Accounting System 1.0 via manipulation of the 'cos_id' argument in /viewin_costumer.php, potentially allowing attackers to execute arbitrary SQL commands.
date: "2026-03-30T20:16:24Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - web-application
  - cve-2026-5150
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5150
  - https://code-projects.org/
  - https://github.com/Xu-Zhihan/CVE/issues/11
  - https://vuldb.com/submit/780199
  - https://vuldb.com/vuln/354183
  - https://vuldb.com/vuln/354183/cti
rules:
  - title: Detect Suspicious SQL Injection Attempts in code-projects Accounting System
    description: Detects potential SQL injection attempts targeting the /viewin_costumer.php endpoint by looking for common SQL syntax within the cos_id parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious SQL Injection Error Messages
    description: Detects potential SQL injection attempts by looking for SQL error messages in the web server logs. This can be indicative of successful or attempted SQL injection attacks.
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

A critical security vulnerability, identified as CVE-2026-5150, has been discovered in code-projects Accounting System version 1.0. The vulnerability resides within the Parameter Handler component, specifically affecting the '/viewin_costumer.php' file.  By maliciously manipulating the 'cos_id' argument, a remote attacker can inject arbitrary SQL commands into the application's database queries.  Given the public disclosure of this exploit, the risk of exploitation is elevated.  Successful…
