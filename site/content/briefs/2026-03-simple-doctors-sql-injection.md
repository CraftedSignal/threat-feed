---
title: SQL Injection Vulnerability in SourceCodester Simple Doctors Appointment System 1.0 (CVE-2026-5179)
slug: 2026-03-simple-doctors-sql-injection
description: A SQL injection vulnerability (CVE-2026-5179) exists in SourceCodester Simple Doctors Appointment System 1.0, allowing remote attackers to execute arbitrary SQL commands by manipulating the Username argument in the /admin/login.php file, with a public exploit available.
date: "2026-03-31T05:16:11Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - web-application
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5179
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5179
  - https://github.com/dyh1213-wq/cve/issues/3
  - https://vuldb.com/vuln/354247
rules:
  - title: Detect SQL Injection Attempt via Username Field
    description: Detects potential SQL injection attempts by monitoring POST requests to /admin/login.php with suspicious characters in the Username field.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Error Messages in Web Responses
    description: Detects potential SQL injection vulnerabilities by monitoring server responses that contain SQL error messages.
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

SourceCodester Simple Doctors Appointment System 1.0 is vulnerable to SQL injection. The vulnerability, identified as CVE-2026-5179, resides in the /admin/login.php file. An attacker can remotely exploit this vulnerability by manipulating the Username argument, injecting malicious SQL commands into the application's database queries. The vulnerability was published on March 31, 2026, and a public exploit is available, increasing the risk of exploitation. This vulnerability could allow attackers…
