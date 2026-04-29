---
title: Daptin SQL Injection Vulnerability in Aggregate API
slug: 2026-04-daptin-sql-injection
description: A SQL injection vulnerability exists in Daptin versions prior to 0.11.4 within the `/aggregate/:typename` endpoint, where the `column` and `group` query parameters are passed to `goqu.L()` without validation, allowing authenticated users to inject arbitrary SQL expressions and exfiltrate sensitive data.
date: "2026-04-23T12:00:00Z"
type: coverage
types:
  - coverage
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

Daptin versions prior to 0.11.4 are susceptible to a SQL injection vulnerability in the `/aggregate/:typename` endpoint. The vulnerability arises because the application fails to properly validate the `column` and `group` query parameters before passing them to `goqu.L()`. This function is used to build raw SQL literal expressions, thus bypassing parameterization and allowing attackers to inject arbitrary SQL code. Any authenticated user, regardless of privilege level, can exploit this vulnerability. This poses a significant risk as it enables unauthorized data extraction, disclosure of database internals, and cross-table data exfiltration. The vulnerability was reported on 2026-04-22 and assigned CVE-2026-41422.

## Attack Chain

1. An attacker authenticates to the Daptin application with valid credentials.
2. The attacker crafts a malicious HTTP GET request targeting the `/aggregate/:typename` endpoint.
3. The attacker injects a SQL payload into the `column` or `group` query parameters. For example, `column=(SELECT group_concat(email) FROM user_account) as leak`.
4. The Daptin application receives the request and passes the unvalidated `column` parameter to the `goqu.L()` function in `server/resource/resource_aggregate.go`.
5. The `goqu.L()` function constructs a raw SQL query using the attacker-controlled input, bypassing any parameterization.
6. The malicious SQL query is executed against the database.
7. The attacker retrieves the injected SQL query's result from the application's response, which contains sensitive data.
8. The attacker exfiltrates the extracted data, potentially including user credentials, internal database schema details, or other confidential information.

## Impact

Successful exploitation of this SQL injection vulnerability allows attackers to perform unauthorized data extraction, including sensitive information like user credentials. An attacker can also disclose database internals and exfiltrate data from multiple tables, even with low-privilege access. The impact includes potential data breaches, compliance violations, and reputational damage. The vulnerability was confirmed to allow extraction of `user_account.email` values by a non-admin user.

## Recommendation

*   Upgrade Daptin to version 0.11.4 or later to patch the SQL injection vulnerability (CVE-2026-41422).
*   Deploy the provided Sigma rule `Detect Daptin Aggregate API SQL Injection` to identify exploitation attempts in web server logs.
*   If upgrading is not immediately feasible, implement input validation on the `column` and `group` parameters in the `/aggregate/:typename` endpoint, specifically blocking SQL keywords and functions to mitigate the risk.
