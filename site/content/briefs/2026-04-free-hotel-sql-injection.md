---
title: SQL Injection Vulnerability in Free Hotel Reservation System 1.0 (CVE-2026-5551)
slug: 2026-04-free-hotel-sql-injection
description: A SQL injection vulnerability (CVE-2026-5551) exists in itsourcecode Free Hotel Reservation System 1.0, specifically affecting the `email` parameter within the `/hotel/admin/login.php` file, allowing remote attackers to execute arbitrary SQL queries.
date: "2026-04-05T09:16:17Z"
severities:
  - high
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
  - id: CVE-2026-5551
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5551
  - https://vuldb.com/vuln/355315
ioc_counts:
  email: 1
rules:
  - title: Detect SQL Injection in Free Hotel Reservation System Login
    description: Detects potential SQL injection attempts in the /hotel/admin/login.php page by looking for SQL keywords in the email parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages in Free Hotel Reservation System
    description: Detects potential SQL injection vulnerabilities by monitoring for common SQL error messages in web server logs related to the hotel login page.
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

itsourcecode Free Hotel Reservation System version 1.0 is vulnerable to SQL injection. The vulnerability, identified as CVE-2026-5551, resides in the `/hotel/admin/login.php` file within the Parameter Handler component. Publicly available exploits target the `email` parameter, allowing unauthenticated remote attackers to inject malicious SQL queries. This vulnerability can lead to unauthorized access to sensitive data, modification of the database, or even complete compromise of the affected…
