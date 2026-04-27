---
title: OpenC3 COSMOS SQL Injection Vulnerability in QuestDB Time-Series Database
slug: 2024-01-09-openc3-sql-injection
description: A SQL injection vulnerability exists in the Time-Series Database (TSDB) component of COSMOS, allowing an authenticated remote user to execute arbitrary SQL commands, including telemetry data disclosure and deletion.
date: "2026-04-23T14:12:02Z"
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

A SQL injection vulnerability has been identified in the OpenC3 COSMOS Time-Series Database (TSDB) component, which utilizes QuestDB. The vulnerability resides within the `tsdb_lookup` function in the `cvt_model.rb` file, where user-supplied input is directly incorporated into SQL queries without proper sanitization. An authenticated attacker with "tlm" permissions, which includes Admin, Operator, Viewer, or Runner roles, can exploit this flaw to inject arbitrary SQL commands. This can lead to…
