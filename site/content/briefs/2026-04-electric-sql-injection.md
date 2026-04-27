---
title: ElectricSQL /v1/shape API SQL Injection Vulnerability
slug: 2026-04-electric-sql-injection
description: The ElectricSQL sync engine is vulnerable to SQL injection, potentially allowing authenticated users to read, write, and destroy the underlying PostgreSQL database.
date: "2026-04-22T12:00:00Z"
severities:
  - critical
tags:
  - sql-injection
  - electricsql
  - postgresql
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40906
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40906
  - https://github.com/electric-sql/electric/pull/4081
  - https://github.com/electric-sql/electric/security/advisories/GHSA-h5rg-pxx7-r2hj
rules:
  - title: Detect Suspicious SQL Injection Attempt in ElectricSQL API Request
    description: Detects potential SQL injection attempts targeting the ElectricSQL /v1/shape API by looking for specific SQL keywords in the order_by parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious SQL Injection Error Messages
    description: Detects potential SQL injection exploitation by identifying common SQL error messages in server responses.
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

Electric, a Postgres sync engine, is vulnerable to SQL injection in the `order_by` parameter of the ElectricSQL `/v1/shape` API endpoint. This vulnerability exists in versions 1.1.12 to before 1.5.0. Exploitation allows any authenticated user to execute arbitrary SQL queries, leading to potential data breaches, data manipulation, and complete database compromise. Successful exploitation can result in unauthorized access to sensitive information, modification of critical data, and denial of…
