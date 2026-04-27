---
title: NocoBase SQL Injection via Missing Validation on Update Endpoint
slug: 2024-01-24-nocobase-sql-injection
description: A SQL injection vulnerability exists in nocobase plugin-collection-sql versions 2.0.32 and earlier due to missing validation on the sqlCollection:update endpoint, allowing attackers with collection management permissions to execute arbitrary SQL queries and exfiltrate data.
date: "2024-01-24T12:00:00Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - nocobase
vendors:
  - nocobase
products:
  - plugin-collection-sql
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-wrwh-c28m-9jjh
rules:
  - title: Detect NocoBase SQL Injection via Update Endpoint
    description: Detects attempts to exploit the SQL injection vulnerability in NocoBase by monitoring POST requests to the sqlCollection:update endpoint with suspicious SQL queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect NocoBase Collection Creation with Blocked SQL Keywords
    description: Detects attempts to create NocoBase collections with SQL queries containing blocked keywords.
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

The `@nocobase/plugin-collection-sql` plugin for NocoBase is vulnerable to SQL injection. Specifically, the `checkSQL()` validation function, responsible for preventing dangerous SQL keywords, is applied to the `collections:create` and `sqlCollection:execute` endpoints, but is absent from the `sqlCollection:update` endpoint. This oversight allows an attacker with collection management permissions (specifically, the `pm.data-source-manager.collection-sql` snippet) to inject arbitrary SQL code…
