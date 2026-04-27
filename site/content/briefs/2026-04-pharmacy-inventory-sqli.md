---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability
slug: 2026-04-pharmacy-inventory-sqli
description: A SQL injection vulnerability (CVE-2026-7194) exists in SourceCodester Pharmacy Sales and Inventory System 1.0, allowing remote attackers to manipulate the ID argument in the /ajax.php?action=save_product endpoint, potentially leading to unauthorized database access.
date: "2026-04-28T12:00:00Z"
severities:
  - high
exploited: true
tags:
  - sqli
  - vulnerability
  - web-application
vendors:
  - SourceCodester
products:
  - Pharmacy Sales and Inventory System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7194
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7194
  - https://github.com/bfs045313-wq/cv3-protect/issues/2
  - https://vuldb.com/submit/800977
  - https://vuldb.com/vuln/359798
  - https://vuldb.com/vuln/359798/cti
  - https://www.sourcecodester.com/
rules:
  - title: Detect SQL Injection Attempts in Pharmacy Inventory System
    description: Detects potential SQL injection attempts targeting the /ajax.php endpoint in SourceCodester Pharmacy Sales and Inventory System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via ID Parameter Manipulation
    description: Detects SQL injection attempts in web requests by identifying specific SQL keywords within the ID parameter.
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

A SQL injection vulnerability has been identified in SourceCodester Pharmacy Sales and Inventory System version 1.0. The vulnerability resides within the `/ajax.php?action=save_product` endpoint, specifically through the manipulation of the `ID` argument. This allows an unauthenticated, remote attacker to inject malicious SQL queries, potentially leading to unauthorized data access, modification, or deletion. The public availability of exploit code increases the risk of active exploitation…
