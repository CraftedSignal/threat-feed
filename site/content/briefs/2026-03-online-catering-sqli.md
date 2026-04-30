---
title: SourceCodester Online Catering Reservation SQL Injection Vulnerability (CVE-2026-4615)
slug: 2026-03-online-catering-sqli
description: A SQL injection vulnerability exists in SourceCodester Online Catering Reservation 1.0's `/search.php` file, allowing remote attackers to execute arbitrary SQL commands by manipulating the `rcode` argument.
date: "2026-03-25T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - cve-2026-4615
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4615
  - https://github.com/WHOAMI-xiaoyu/CVE/blob/main/CVE_5.md
  - https://vuldb.com/?ctiid.352479
  - https://vuldb.com/?id.352479
  - https://vuldb.com/?submit.775735
  - https://www.sourcecodester.com/
ioc_counts:
  url: 5
rules:
  - title: Detect SQL Injection Attempts in Online Catering Reservation
    description: Detects potential SQL injection attempts targeting the /search.php endpoint by looking for SQL keywords in the rcode parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect potential SQL Injection via rcode Parameter
    description: Detects potential SQL injection attacks targeting the rcode parameter using common SQL syntax
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

SourceCodester Online Catering Reservation 1.0 is vulnerable to SQL injection, as identified by CVE-2026-4615. The vulnerability resides within the `/search.php` file and can be triggered by manipulating the `rcode` argument. This allows a remote attacker to inject arbitrary SQL queries into the application's database, potentially leading to data breaches, modification of data, or complete compromise of the database server. The vulnerability was reported on March 23, 2026, and a public exploit…
