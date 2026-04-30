---
title: SQL Injection Vulnerability in itsourcecode Online Enrollment System 1.0 (CVE-2026-4632)
slug: 2026-03-online-enrollment-sqli
description: CVE-2026-4632 is a SQL Injection vulnerability in itsourcecode Online Enrollment System 1.0, specifically affecting the Parameter Handler component at '/sms/user/index.php?view=add', allowing a remote attacker to inject malicious SQL code by manipulating the 'Name' argument, with a public exploit available.
date: "2026-03-24T05:16:24Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - web-application
  - cve-2026-4632
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4632
  - https://github.com/chuxina7-aiguo/CVE1/issues/1
  - https://itsourcecode.com/
  - https://vuldb.com/?ctiid.352499
  - https://vuldb.com/?id.352499
  - https://vuldb.com/?submit.775856
rules:
  - title: Detect SQL Injection Attempts in Online Enrollment System
    description: Detects potential SQL injection attempts targeting the /sms/user/index.php endpoint in itsourcecode Online Enrollment System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempts in Online Enrollment System (POST)
    description: Detects potential SQL injection attempts targeting the /sms/user/index.php endpoint in itsourcecode Online Enrollment System using POST method.
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

A SQL Injection vulnerability, identified as CVE-2026-4632, has been discovered in itsourcecode Online Enrollment System version 1.0. The vulnerability resides within the Parameter Handler component of the application, specifically in the `/sms/user/index.php?view=add` file. By manipulating the `Name` argument, a remote attacker can inject malicious SQL code, potentially leading to unauthorized data access, modification, or deletion. The existence of a publicly available exploit increases the…
