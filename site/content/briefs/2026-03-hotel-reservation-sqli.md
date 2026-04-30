---
title: SQL Injection Vulnerability in Free Hotel Reservation System 1.0
slug: 2026-03-hotel-reservation-sqli
description: A SQL injection vulnerability (CVE-2026-4612) exists in itsourcecode Free Hotel Reservation System 1.0 within the Parameter Handler component, allowing remote attackers to execute arbitrary SQL commands via the account_id parameter in the /hotel/admin/mod_users/index.php script.
date: "2026-03-24T14:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-4612
  - sql-injection
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4612
  - https://github.com/bybinyu/Vulnerability-Practice/issues/2
  - https://vuldb.com/?id.352476
rules:
  - title: Detect SQL Injection Attempt via Account ID
    description: Detects potential SQL injection attempts targeting the account_id parameter in the Free Hotel Reservation System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt via URI
    description: Detects potential SQL injection attempts based on suspicious keywords in the URI.
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

The itsourcecode Free Hotel Reservation System 1.0 is vulnerable to SQL injection (CVE-2026-4612). The vulnerability resides in the Parameter Handler component, specifically affecting the `/hotel/admin/mod_users/index.php` script. By manipulating the `account_id` parameter, a remote attacker can inject arbitrary SQL commands into the application's database queries. The vulnerability was reported in March 2026 and has a CVSS v3.1 score of 7.3 (HIGH). Publicly available exploit code increases the…
