---
title: Dagster SQL Injection Vulnerability in Dynamic Partition Keys
slug: 2024-01-02-dagster-sqli
description: A SQL injection vulnerability exists in Dagster's DuckDB, Snowflake, BigQuery, and DeltaLake I/O managers, where a user with 'Add Dynamic Partitions' permission can inject arbitrary SQL due to improper escaping of dynamic partition key values, leading to unauthorized data access or modification.
date: "2026-04-18T01:07:59Z"
type: coverage
types:
  - coverage
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

A SQL injection vulnerability has been identified in Dagster's I/O managers for DuckDB, Snowflake, BigQuery, and DeltaLake. The vulnerability stems from the construction of SQL WHERE clauses where dynamic partition key values are interpolated into queries without proper escaping. This allows an attacker with the `Add Dynamic Partitions` permission to inject arbitrary SQL code. The injected SQL would then execute against the target database backend using the I/O manager's credentials. This issue affects Dagster OSS versions up to 1.13.0, and dagster-* package versions up to 0.29.0. This vulnerability is most relevant when the `Add Dynamic Partitions` permission is granted independently of broader database access, such as in multi-tenant or custom RBAC configurations.

## Attack Chain

1. An attacker gains access to the Dagster API with the `Add Dynamic Partitions` permission. This could be through compromised credentials or a misconfigured RBAC setup.
2. The attacker crafts a malicious dynamic partition key containing SQL injection payloads.
3. The attacker uses the Dagster API to create a new dynamic partition or modify an existing one, injecting the malicious key.
4. A Dagster pipeline or asset execution is triggered that utilizes the dynamic partitions functionality and the vulnerable I/O manager.
5. When the I/O manager constructs the SQL query, the malicious partition key is interpolated without proper escaping.
6. The injected SQL code is executed against the target database (DuckDB, Snowflake, BigQuery, or DeltaLake) using the I/O manager's credentials.
7. The attacker can read sensitive data, modify existing data, or potentially escalate privileges within the database.
8. The attacker achieves their final objective, such as exfiltrating data or compromising the database's integrity.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to unauthorized access and modification of data within the affected databases. The impact is particularly high in deployments where the `Add Dynamic Partitions` permission is granted to users without broader database access. This vulnerability could allow attackers to bypass intended access controls and potentially gain full control of the database, leading to data breaches, data corruption, or denial of service. The number of affected deployments is currently unknown, but organizations using Dagster with dynamic partitions should assess their exposure.

## Recommendation

*   Upgrade all `dagster-*` packages (dagster-duckdb, dagster-snowflake, dagster-gcp, dagster-deltalake, dagster-snowflake-polars) to versions greater than 0.29.0 and `dagster` package to versions greater than 1.13.0 as outlined in the advisory to remediate the vulnerability.
*   Review user roles and permissions within Dagster, specifically focusing on who has the `Add Dynamic Partitions` permission, and restrict access to only trusted users to reduce the attack surface.
*   Monitor Dagster logs for suspicious API requests related to the creation or modification of dynamic partitions to detect potential exploitation attempts.
*   Implement database auditing to track SQL queries executed by the I/O manager and identify potential SQL injection attempts.
