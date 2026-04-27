---
title: PostgreSQL JDBC Driver SQL Injection Vulnerability
slug: 2024-06-postgresql-jdbc-injection
description: An anonymous, remote attacker can exploit a vulnerability in the PostgreSQL JDBC Driver to perform SQL injection attacks.
date: "2026-03-24T10:21:21Z"
severities:
  - high
tags:
  - sql-injection
  - postgresql
  - jdbc
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2024-0424
rules:
  - title: Detect Potential SQL Injection Attempts in HTTP Requests
    description: Detects potential SQL injection attempts by identifying common SQL keywords in HTTP request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Potential SQL Injection Attempts in HTTP Request Body
    description: Detects potential SQL injection attempts by identifying common SQL keywords in HTTP request body.
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

A vulnerability exists within the PostgreSQL JDBC Driver that allows for SQL injection attacks. The specifics of the vulnerable versions are not provided, however, exploitation allows a remote, unauthenticated attacker to inject arbitrary SQL commands into the application's database queries. This can lead to data exfiltration, modification, or even complete database compromise. The lack of specific version information makes targeted patching difficult, emphasizing the need for broad detection…
