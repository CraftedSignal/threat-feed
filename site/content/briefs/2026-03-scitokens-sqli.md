---
title: SciTokens KeyCache SQL Injection Vulnerability (CVE-2026-32714)
slug: 2026-03-scitokens-sqli
description: A SQL injection vulnerability exists in SciTokens versions before 1.9.6, allowing attackers to execute arbitrary SQL commands via the KeyCache class by manipulating user-supplied data used in SQL query construction.
date: "2026-03-31T03:15:55Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - scitokens
  - cve-2026-32714
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
cves:
  - id: CVE-2026-32714
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32714
  - https://github.com/scitokens/scitokens/commit/3dba108853f2f4a6c0f2325c03779bf083c41cf2
  - https://github.com/scitokens/scitokens/releases/tag/v1.9.6
  - https://github.com/scitokens/scitokens/security/advisories/GHSA-rh5m-2482-966c
rules:
  - title: Detect Suspicious Processes Accessing SQLite Databases
    description: Detects processes that are not typically associated with SQLite database access and may indicate exploitation of CVE-2026-32714
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect SciTokens process with SQL injection attempt
    description: Detects potential SQL injection attempts in SciTokens by monitoring command line parameters of python processes related to SciTokens.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

SciTokens is a reference library for generating and using SciTokens. A critical SQL injection vulnerability, identified as CVE-2026-32714, affects SciTokens versions prior to 1.9.6. The vulnerability resides within the `KeyCache` class, which improperly utilizes Python's `str.format()` to construct SQL queries. This allows an attacker to inject arbitrary SQL commands by manipulating user-supplied data, such as the `issuer` and `key_id` parameters, during interactions with the local SQLite…
