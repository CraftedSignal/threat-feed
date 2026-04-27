---
title: SQL Injection Vulnerability in projectworlds Car Rental System 1.0
slug: 2026-04-car-rental-sql-injection
description: A SQL injection vulnerability (CVE-2026-5637) exists in projectworlds Car Rental System 1.0's /message_admin.php, allowing remote attackers to execute arbitrary SQL commands by manipulating the 'Message' argument.
date: "2026-04-06T09:16:18Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-5637
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5637
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5637
  - https://github.com/eqiya17/collection-of-vulnerabilities/issues/13
  - https://vuldb.com/vuln/355425
rules:
  - title: Detect SQL Injection Attempt in Car Rental System
    description: Detects potential SQL injection attempts targeting the projectworlds Car Rental System 1.0 by monitoring for suspicious SQL syntax in the 'Message' parameter within requests to '/message_admin.php'.
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
  - title: Detect Possible SQL Injection via URI on Linux Web Servers
    description: Detects possible SQL injection attempts by looking for common SQL injection syntax in URI requests on Linux web servers.
    platform: sigma
    severity: medium
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

A SQL injection vulnerability has been identified in projectworlds Car Rental System version 1.0. This flaw is located within the `/message_admin.php` file, specifically affecting the Parameter Handler component. By manipulating the `Message` argument, a remote attacker can inject malicious SQL code, potentially leading to unauthorized data access or modification. The vulnerability, assigned CVE-2026-5637, has a CVSS v3.1 score of 7.3, indicating a high severity. Public exploit code is…
