---
title: OpenC3 COSMOS SQL Injection Vulnerability in QuestDB Time-Series Database
slug: 2024-01-09-openc3-sql-injection
description: A SQL injection vulnerability exists in the Time-Series Database (TSDB) component of COSMOS, allowing an authenticated remote user to execute arbitrary SQL commands, including telemetry data disclosure and deletion.
date: "2026-04-23T14:12:02Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - sql-injection
  - openc3
  - cosmos
  - questdb
  - telemetry
vendors:
  - rubygems
products:
  - OpenC3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1202
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-v529-vhwc-wfc5
rules:
  - title: Detect Suspicious OpenC3 Telemetry Requests
    description: Detects suspicious requests to the OpenC3 `get_tlm_values` endpoint potentially indicative of SQL injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Payloads in OpenC3 Telemetry API
    description: This rule detects common SQL injection payloads within requests to the OpenC3 telemetry API endpoint. It looks for the presence of SQL keywords and comment sequences within the request URI.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in the OpenC3 COSMOS Time-Series Database (TSDB) component, which utilizes QuestDB. The vulnerability resides within the `tsdb_lookup` function in the `cvt_model.rb` file, where user-supplied input is directly incorporated into SQL queries without proper sanitization. An authenticated attacker with "tlm" permissions, which includes Admin, Operator, Viewer, or Runner roles, can exploit this flaw to inject arbitrary SQL commands. This can lead to unauthorized data access, modification, or deletion within the TSDB. The affected versions are OpenC3 rubygems package versions >= 6.7.0 and < 7.0.0-rc3. Successful exploitation allows attackers to compromise the confidentiality, integrity, and availability of telemetry data stored within the COSMOS system.

## Attack Chain

1.  An attacker authenticates to the COSMOS system with a role that possesses "tlm" permissions (Admin, Operator, Viewer, or Runner).
2.  The attacker crafts a malicious JSON-RPC request targeting the `get_tlm_values` endpoint.
3.  Within the request body, the attacker injects a SQL payload into the `start_time` parameter, such as `' OR 1=1 --`.
4.  The `tsdb_lookup` function incorporates the unsanitized input into a SQL query.
5.  The injected SQL payload manipulates the query logic, allowing the attacker to bypass intended restrictions.
6.  The attacker can then exfiltrate all telemetry data within the database by manipulating the SQL query.
7.  The attacker modifies the SQL payload to execute arbitrary commands, such as `DROP TABLE` statements.
8.  The attacker successfully deletes historical data from the database, impacting data availability and system integrity.

## Impact

Successful exploitation of this SQL injection vulnerability allows an attacker to perform unauthorized actions on the OpenC3 COSMOS Time-Series Database (TSDB). An attacker with "tlm" permissions can disclose sensitive telemetry data, modify existing data, or delete data altogether. The vulnerability impacts systems running OpenC3 rubygems package versions >= 6.7.0 and < 7.0.0-rc3. Depending on the role of the compromised account and the specific SQL commands executed, an attacker could potentially cause significant disruption to operations relying on the integrity and availability of telemetry data.

## Recommendation

*   Upgrade the `rubygems/openc3` package to version 7.0.0-rc3 or later to remediate the SQL injection vulnerability.
*   Implement input sanitization on user-supplied data within the `tsdb_lookup` function in `cvt_model.rb` to prevent SQL injection attacks.
*   Deploy the Sigma rule "Detect Suspicious OpenC3 Telemetry Requests" to identify potential exploitation attempts targeting the `get_tlm_values` endpoint.
*   Review and restrict "tlm" permissions to the `get_tlm_values` RPC endpoint according to the principle of least privilege, limiting access to only those users who require it.
