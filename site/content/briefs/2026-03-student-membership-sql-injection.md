---
title: SQL Injection Vulnerability in Student Membership System 1.0
slug: 2026-03-student-membership-sql-injection
description: CVE-2026-5198 is a SQL injection vulnerability in the Admin Login component of code-projects Student Membership System 1.0, affecting the /admin/index.php file, enabling remote exploitation through manipulation of username/password parameters.
date: "2026-03-31T12:16:31Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5198
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5198
  - https://code-projects.org/
  - https://github.com/maidangdang1/CVE/issues/4
  - https://vuldb.com/submit/780403
  - https://vuldb.com/vuln/354296
  - https://vuldb.com/vuln/354296/cti
rules:
  - title: Detect Suspicious Login Attempts with SQL Injection Patterns
    description: Detects suspicious login attempts to /admin/index.php with potential SQL injection payloads in username or password fields.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages
    description: Detects server error messages indicative of SQL injection attempts.
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

A SQL injection vulnerability, identified as CVE-2026-5198, exists within the code-projects Student Membership System version 1.0. Specifically, the vulnerability lies within the Admin Login component's `/admin/index.php` file. Attackers can remotely exploit this vulnerability by manipulating the `username` and `password` parameters, leading to arbitrary SQL command execution. Public exploit code is available, increasing the risk of widespread exploitation. This vulnerability poses a…
