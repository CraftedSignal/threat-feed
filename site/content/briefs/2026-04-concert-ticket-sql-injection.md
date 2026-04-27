---
title: SQL Injection Vulnerability in Concert Ticket Reservation System
slug: 2026-04-concert-ticket-sql-injection
description: A remote attacker can exploit CVE-2026-5554 in code-projects Concert Ticket Reservation System 1.0 to perform SQL injection by manipulating the searching argument in the process_search.php file.
date: "2026-04-05T10:16:18Z"
severities:
  - high
exploited: true
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
  - id: CVE-2026-5554
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5554
  - https://code-projects.org/
  - https://github.com/Wzl731/test/issues/4
  - https://vuldb.com/submit/782874
  - https://vuldb.com/vuln/355324
  - https://vuldb.com/vuln/355324/cti
rules:
  - title: Detecting SQL Injection Attempts
    description: Detects potential SQL injection attempts in HTTP requests by identifying common SQL keywords and syntax.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting SQL Injection in process_search.php
    description: Detects SQL Injection attempts specifically targeting process_search.php
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

CVE-2026-5554 details a SQL injection vulnerability affecting code-projects Concert Ticket Reservation System version 1.0. The vulnerability resides within the `/ConcertTicketReservationSystem-master/process_search.php` file, specifically in how the Parameter Handler component processes search arguments. A remote attacker can manipulate the `searching` argument to inject arbitrary SQL commands. Publicly available exploits exist, increasing the risk of active exploitation. Successful…
