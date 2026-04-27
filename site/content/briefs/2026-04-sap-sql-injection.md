---
title: SAP Business Planning and Consolidation and Business Warehouse SQL Injection Vulnerability
slug: 2026-04-sap-sql-injection
description: CVE-2026-27681 describes an insufficient authorization check vulnerability in SAP Business Planning and Consolidation and SAP Business Warehouse that allows authenticated users to execute crafted SQL statements, leading to unauthorized data access, modification, and deletion.
date: "2026-04-14T00:16:06Z"
severities:
  - critical
tags:
  - cve-2026-27681
  - sql-injection
  - sap
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-27681
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27681
  - https://me.sap.com/notes/3719353
  - https://url.sap/sapsecuritypatchday
rules:
  - title: Detect Suspicious SAP SQL Injection Attempts
    description: Detects potential SQL injection attempts in SAP applications based on suspicious keywords in HTTP request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious SAP SQL Injection Attempts via POST
    description: Detects potential SQL injection attempts in SAP applications based on suspicious keywords in HTTP POST requests.
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

CVE-2026-27681 highlights a critical security flaw within SAP Business Planning and Consolidation and SAP Business Warehouse. This vulnerability stems from insufficient authorization checks, which allows an authenticated user to inject and execute arbitrary SQL commands. The vulnerability was published on 2026-04-13. An attacker can leverage this flaw to perform unauthorized actions such as reading sensitive data, modifying critical system configurations, and deleting essential information. The…
