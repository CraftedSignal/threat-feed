---
title: Daptin SQL Injection Vulnerability in Aggregate API
slug: 2026-04-daptin-sql-injection
description: A SQL injection vulnerability exists in Daptin versions prior to 0.11.4 within the `/aggregate/:typename` endpoint, where the `column` and `group` query parameters are passed to `goqu.L()` without validation, allowing authenticated users to inject arbitrary SQL expressions and exfiltrate sensitive data.
date: "2026-04-23T12:00:00Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
vendors:
  - Daptin
products:
  - Daptin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://github.com/advisories/GHSA-rw2c-8rfq-gwfv
rules:
  - title: Detect Daptin Aggregate API SQL Injection
    description: Detects potential SQL injection attempts in Daptin's `/aggregate/:typename` endpoint by identifying suspicious SQL syntax within the `column` or `group` query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Daptin Aggregate API Database Schema Disclosure
    description: Detects attempts to disclose database schema in Daptin's `/aggregate/:typename` endpoint using sqlite_master.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Daptin versions prior to 0.11.4 are susceptible to a SQL injection vulnerability in the `/aggregate/:typename` endpoint. The vulnerability arises because the application fails to properly validate the `column` and `group` query parameters before passing them to `goqu.L()`. This function is used to build raw SQL literal expressions, thus bypassing parameterization and allowing attackers to inject arbitrary SQL code. Any authenticated user, regardless of privilege level, can exploit this…
