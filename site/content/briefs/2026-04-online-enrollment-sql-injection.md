---
title: itsourcecode Online Enrollment System SQL Injection Vulnerability (CVE-2026-5534)
slug: 2026-04-online-enrollment-sql-injection
description: CVE-2026-5534 is a SQL injection vulnerability in the itsourcecode Online Enrollment System 1.0 that allows remote attackers to execute arbitrary SQL commands by manipulating the USERID parameter in the /sms/user/index.php file, potentially leading to data exfiltration or unauthorized access.
date: "2026-04-05T03:16:00Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-5534
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5534
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5534
  - https://github.com/ldan42008-ux/cve/issues/2
  - https://vuldb.com/vuln/355287
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect SQL Injection in Online Enrollment System
    description: Detects potential SQL injection attempts targeting the itsourcecode Online Enrollment System via suspicious parameters in HTTP GET requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Vulnerable Enrollment Endpoint
    description: Detects access to the vulnerable /sms/user/index.php endpoint in itsourcecode Online Enrollment System.
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

The itsourcecode Online Enrollment System version 1.0 is vulnerable to SQL injection via the USERID parameter in the `/sms/user/index.php` file. This vulnerability, identified as CVE-2026-5534, allows an unauthenticated, remote attacker to inject arbitrary SQL commands into the application's database queries. The vulnerability stems from insufficient sanitization of user-supplied input, leading to potential data breaches and unauthorized modification of enrollment data. This vulnerability has a…
