---
title: Oracle MySQL Multiple Vulnerabilities
slug: 2026-03-mysql-vulns
description: A remote attacker, either anonymous or authenticated, can exploit multiple vulnerabilities in Oracle MySQL to compromise confidentiality, integrity, and availability.
date: "2026-03-24T12:40:50Z"
severities:
  - critical
tags:
  - mysql
  - vulnerability
  - database
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0168
rules:
  - title: Detect Unusual Process Spawned by MySQL
    description: Detects processes spawned by the MySQL daemon that are not typically associated with database operations, potentially indicating exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect MySQL User Privilege Escalation Attempts
    description: Detects attempts to grant elevated privileges to MySQL users, potentially indicating malicious activity or unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

This advisory from the German BSI highlights the risk of multiple vulnerabilities affecting Oracle MySQL. An attacker, either unauthenticated or authenticated, can remotely exploit these weaknesses. Successful exploitation could lead to complete compromise of the MySQL server, including unauthorized access to sensitive data, modification of data, and denial of service. The advisory does not specify particular versions or CVEs, indicating a broad range of potential issues. Defenders should…
