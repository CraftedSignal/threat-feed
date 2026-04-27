---
title: NocoBase SQL Injection via Recursive Eager Loading
slug: 2024-01-nocobase-sqli
description: NocoBase versions 2.0.32 and earlier are vulnerable to SQL injection due to string concatenation in the `queryParentSQL()` function, allowing attackers with record creation permissions to inject arbitrary SQL and potentially extract sensitive information or execute commands.
date: "2024-01-03T12:00:00Z"
severities:
  - critical
tags:
  - sqli
  - nocobase
  - cve-2026-41640
  - injection
vendors:
  - NocoBase
products:
  - NocoBase
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-4948-f92q-f432
rules:
  - title: Detect NocoBase SQL Injection Attempt in Primary Key
    description: Detects potential SQL injection attempts in NocoBase primary keys by searching for SQL metacharacters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect NocoBase UNION ALL Injection
    description: Detects SQL injection attempts using UNION ALL in NocoBase web requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability exists in NocoBase version 2.0.32 and earlier due to string concatenation in the `queryParentSQL()` function within the `@nocobase/database` core package. The vulnerability stems from how the `queryParentSQL()` function constructs a recursive CTE query by concatenating `nodeIds` instead of using parameterized queries. An attacker with record creation permissions on a tree collection with string-type primary keys can inject arbitrary SQL via a malicious string…
