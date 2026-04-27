---
title: Dagster SQL Injection Vulnerability in Dynamic Partition Keys
slug: 2024-01-02-dagster-sqli
description: A SQL injection vulnerability exists in Dagster's DuckDB, Snowflake, BigQuery, and DeltaLake I/O managers, where a user with 'Add Dynamic Partitions' permission can inject arbitrary SQL due to improper escaping of dynamic partition key values, leading to unauthorized data access or modification.
date: "2026-04-18T01:07:59Z"
severities:
  - high
tags:
  - sqli
  - dagster
  - injection
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-mjw2-v2hm-wj34
rules:
  - title: Detect Dynamic Partition Creation with Suspicious Characters
    description: Detects attempts to create or modify dynamic partitions with potentially malicious characters indicative of SQL injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Database Errors Following Dynamic Partition Update
    description: Detects database errors occurring shortly after a dynamic partition update, which might indicate a successful SQL injection.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in Dagster's I/O managers for DuckDB, Snowflake, BigQuery, and DeltaLake. The vulnerability stems from the construction of SQL WHERE clauses where dynamic partition key values are interpolated into queries without proper escaping. This allows an attacker with the `Add Dynamic Partitions` permission to inject arbitrary SQL code. The injected SQL would then execute against the target database backend using the I/O manager's credentials. This issue…
