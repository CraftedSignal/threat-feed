---
title: SQL Injection Vulnerability in itsourcecode Online Enrollment System 1.0
slug: 2026-04-online-enrollment-sql-injection
description: A SQL injection vulnerability exists in itsourcecode Online Enrollment System 1.0 within the Parameter Handler component at /enrollment/index.php, where manipulating the deptid argument can lead to remote code execution, with public exploits available.
date: "2026-04-02T14:16:37Z"
severities:
  - high
exploited: true
tags:
  - sql-injection
  - web-application
  - cve-2026-5334
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5334
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5334
  - https://github.com/yuji0903/silver-guide/issues/15
  - https://itsourcecode.com/
  - https://vuldb.com/vuln/354668
rules:
  - title: Detect SQL Injection Attempt via deptid Parameter
    description: Detects potential SQL injection attempts targeting the deptid parameter in the /enrollment/index.php endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Request to Vulnerable Enrollment Endpoint
    description: Detects requests to the vulnerable endpoint /enrollment/index.php?view=edit&id=3 which may be an attempt to exploit CVE-2026-5334
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

A SQL injection vulnerability has been identified in itsourcecode Online Enrollment System version 1.0. The vulnerability resides within the Parameter Handler component of the application, specifically affecting the `/enrollment/index.php` endpoint. By manipulating the `deptid` argument, a remote attacker can inject malicious SQL queries, potentially leading to unauthorized data access, modification, or even remote code execution. This vulnerability is particularly concerning because a public…
