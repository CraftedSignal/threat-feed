---
title: Kados R10 GreenBee SQL Injection Vulnerability (CVE-2019-25702)
slug: 2026-04-kados-r10-greenbee-sqli
description: Kados R10 GreenBee is vulnerable to SQL injection via the id_project parameter, allowing attackers to manipulate database queries to extract sensitive information or modify data.
date: "2026-04-05T21:16:48Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2019-25702
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25702
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25702
  - https://www.vulncheck.com/advisories/kados-r10-greenbee-sql-injection-via-id-project-parameter
rules:
  - title: Detect Suspicious SQL Injection Attempts in Kados R10 GreenBee
    description: Detects potential SQL injection attempts in Kados R10 GreenBee by monitoring HTTP requests containing SQL keywords in the id_project parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Error Based SQL Injection in Kados R10 Greenbee
    description: Detects error-based SQL injection by looking for specific SQL keywords and error messages in HTTP responses.
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

Kados R10 GreenBee is susceptible to SQL injection attacks due to improper input validation of the `id_project` parameter. This vulnerability, identified as CVE-2019-25702, allows a remote attacker to inject arbitrary SQL code into database queries. By crafting malicious requests, an attacker can potentially extract sensitive data, modify existing records, or even gain unauthorized access to the underlying database. The vulnerability was published on April 5, 2026, and poses a significant risk…
