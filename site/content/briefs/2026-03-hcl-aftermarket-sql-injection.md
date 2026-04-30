---
title: HCL Aftermarket DPC SQL Injection Vulnerability (CVE-2025-55262)
slug: 2026-03-hcl-aftermarket-sql-injection
description: CVE-2025-55262 is a SQL Injection vulnerability affecting HCL Aftermarket DPC, allowing an attacker to retrieve sensitive information from the database and potentially gain unauthorized access.
date: "2026-03-26T14:16:07Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2025-55262
  - sql-injection
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-55262
  - https://support.hcl-software.com/csm?id=kb_article&sysparm_article=KB0129793
rules:
  - title: Detect Suspicious SQL Injection Attempts via URI
    description: Detects potential SQL injection attempts based on common SQL syntax in URI queries.
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
  - title: Detect Suspicious SQL Injection Attempts via POST data
    description: Detects potential SQL injection attempts based on common SQL syntax in POST data.
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
rules_count: 2
---

A SQL Injection vulnerability, identified as CVE-2025-55262, affects HCL Aftermarket DPC. This vulnerability allows an attacker to inject malicious SQL code into input fields, which can then be executed by the database. Successful exploitation could lead to the retrieval of sensitive information from the database, potentially exposing user credentials, financial data, or other confidential information. The vulnerability was reported by HCL Software and has a CVSS v3.1 score of 8.3, indicating a…
