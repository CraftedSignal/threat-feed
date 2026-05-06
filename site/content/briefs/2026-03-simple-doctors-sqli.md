---
title: SQL Injection Vulnerability in SourceCodester Simple Doctors Appointment System 1.0 (CVE-2026-5180)
slug: 2026-03-simple-doctors-sqli
description: A SQL Injection vulnerability (CVE-2026-5180) exists in SourceCodester Simple Doctors Appointment System 1.0, allowing remote attackers to execute arbitrary SQL commands by manipulating the 'email' parameter in the /admin/ajax.php?action=login2 endpoint.
date: "2026-03-31T05:16:12Z"
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
  - id: CVE-2026-5180
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5180
  - http://github.com/dyh1213-wq/cve/issues/4
  - https://vuldb.com/submit/780354
  - https://vuldb.com/vuln/354248
  - https://vuldb.com/vuln/354248/cti
  - https://www.sourcecodester.com/
rules:
  - title: Detect SQL Injection Attempts in Simple Doctors Appointment System
    description: Detects potential SQL injection attempts targeting the /admin/ajax.php endpoint in Simple Doctors Appointment System
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect Access to admin/ajax.php
    description: Detects access to admin/ajax.php which may indicate malicious activity
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SourceCodester Simple Doctors Appointment System 1.0 is vulnerable to SQL Injection (CVE-2026-5180). The vulnerability is located in the `/admin/ajax.php?action=login2` endpoint, specifically the `email` parameter. A remote attacker can inject arbitrary SQL commands by manipulating this parameter. The vulnerability has been confirmed and an exploit is publicly available, increasing the risk of widespread exploitation. Successful exploitation can lead to unauthorized data access, modification…
