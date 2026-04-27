---
title: SQL Injection Vulnerability in Car Rental Project 1.0 (CVE-2026-5634)
slug: 2026-04-car-rental-sqli
description: A remote SQL injection vulnerability (CVE-2026-5634) exists in projectworlds Car Rental Project 1.0 via the fname parameter in /book_car.php, allowing unauthenticated attackers to potentially read, modify, or delete database information.
date: "2026-04-06T12:00:00Z"
severities:
  - high
tags:
  - sqli
  - web-application
  - cve-2026-5634
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5634
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5634
  - https://github.com/eqiya17/collection-of-vulnerabilities/issues/12
  - https://vuldb.com/submit/785863
  - https://vuldb.com/vuln/355422
  - https://vuldb.com/vuln/355422/cti
ioc_counts:
  email: 1
  url: 4
rules:
  - title: Detect SQL Injection Attempts in Car Rental Project via fname Parameter
    description: Detects potential SQL injection attempts in the /book_car.php endpoint by monitoring for SQL syntax in the fname parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection UNION Based in Car Rental Project via fname Parameter
    description: Detects potential SQL injection attempts with UNION clauses in the /book_car.php endpoint by monitoring for SQL syntax in the fname parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A publicly disclosed SQL injection vulnerability affects projectworlds Car Rental Project version 1.0. This vulnerability, identified as CVE-2026-5634, resides in the `/book_car.php` file, specifically within the parameter handler. An attacker can remotely manipulate the `fname` argument to inject arbitrary SQL commands. Given the availability of exploit code, the risk of exploitation is elevated. Successful exploitation could lead to unauthorized data access, modification, or deletion…
