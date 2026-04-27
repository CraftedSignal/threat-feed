---
title: SQL Injection Vulnerability in jkev Record Management System 1.0 (CVE-2026-5575)
slug: 2026-04-jkev-sql-injection
description: A SQL injection vulnerability (CVE-2026-5575) exists in the Login component of SourceCodester/jkev Record Management System 1.0, allowing remote attackers to execute arbitrary SQL commands by manipulating the Username parameter in index.php.
date: "2026-04-05T15:16:43Z"
severities:
  - high
tags:
  - sql-injection
  - cve-2026-5575
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5575
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5575
  - https://github.com/whatyourname12345/CVE/blob/main/PRMS/cve_SQL.md
  - https://vuldb.com/vuln/355345
rules:
  - title: Detecting JKEV Record Management System SQL Injection Attempt
    description: Detects potential SQL injection attempts in the Username parameter of the JKEV Record Management System login page.
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
  - title: Detecting JKEV Record Management System SQL Injection via POST
    description: Detects potential SQL injection attempts in the Username parameter of the JKEV Record Management System login page using POST requests.
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
rules_count: 2
---

CVE-2026-5575 is a critical security flaw discovered in SourceCodester/jkev Record Management System version 1.0. Specifically, a SQL injection vulnerability is present within the Login component's index.php file. The vulnerability allows unauthenticated, remote attackers to inject malicious SQL code via the Username parameter. Given that an exploit is publicly available, the risk of exploitation is elevated. This could lead to unauthorized data access, modification, or deletion, potentially…
