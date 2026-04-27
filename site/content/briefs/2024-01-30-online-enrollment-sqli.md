---
title: SQL Injection Vulnerability in itsourcecode Online Enrollment System 1.0
slug: 2024-01-30-online-enrollment-sqli
description: A remote SQL injection vulnerability exists in itsourcecode Online Enrollment System 1.0 within the Parameter Handler component affecting the `/sms/grades/index.php` file, allowing unauthorized database access and has been publicly disclosed.
date: "2026-03-26T05:16:41Z"
severities:
  - high
tags:
  - sqli
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4842
rules:
  - title: Detect SQL Injection Attempt in Online Enrollment System
    description: Detects potential SQL injection attempts targeting the itsourcecode Online Enrollment System via the deptid parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect potential SQL injection via URI
    description: Detects potential SQL injection in URI.
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

A critical SQL injection vulnerability has been identified in itsourcecode Online Enrollment System version 1.0. The vulnerability resides within the Parameter Handler component, specifically affecting the `/sms/grades/index.php` file when handling the `deptid` argument. This flaw allows unauthenticated remote attackers to inject arbitrary SQL commands, potentially leading to unauthorized data access, modification, or deletion. Given the public disclosure of the exploit, the risk of…
