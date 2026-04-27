---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability
slug: 2026-04-pharmacy-sqli
description: A remote SQL injection vulnerability exists in SourceCodester Pharmacy Sales and Inventory System 1.0 via manipulation of the ID parameter in the /ajax.php?action=delete_category endpoint, potentially leading to unauthorized data access or modification.
date: "2026-04-28T12:00:00Z"
severities:
  - high
tags:
  - sqli
  - web-application
  - cve-2026-7130
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
  - id: CVE-2026-7130
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7130
  - https://github.com/lonelyuan/vunls/issues/11
  - https://vuldb.com/vuln/359729
rules:
  - title: Detect SQL Injection Attempt in Pharmacy Sales System
    description: Detects potential SQL injection attempts targeting the /ajax.php endpoint by looking for common SQL syntax in the ID parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect Hex Encoded SQL Injection in Pharmacy Sales System
    description: Detects potential SQL injection attempts using hex encoding in the /ajax.php endpoint.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in SourceCodester Pharmacy Sales and Inventory System version 1.0. The vulnerability resides within the `/ajax.php?action=delete_category` endpoint, where a manipulation of the `ID` argument can lead to arbitrary SQL command execution. This allows remote attackers to potentially bypass authentication, access sensitive data, modify database contents, or even compromise the entire system. Given the availability of a published exploit, this…
