---
title: Parse Server PostgreSQL Adapter SQL Injection Vulnerability
slug: 2024-01-02-parse-server-sqli
description: A SQL injection vulnerability in Parse Server's PostgreSQL adapter allows an attacker with master key access to execute arbitrary SQL statements via crafted field names in aggregate `$group` or `distinct` operations, leading to privilege escalation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - privilege-escalation
  - parse-server
vendors:
  - Parse
products:
  - Parse Server
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-p2w6-rmh7-w8q3
rules:
  - title: Detect Suspicious Parse Server PostgreSQL Queries
    description: Detects suspicious SQL queries in PostgreSQL logs indicative of SQL injection attempts targeting Parse Server.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - database
      - postgresql
  - title: Detect Parse Server API Request with SQL Injection Payloads
    description: Detects Parse Server API requests containing common SQL injection payloads.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in the PostgreSQL adapter of Parse Server versions prior to 8.6.59 and between 9.0.0 and 9.6.0-alpha.53. This flaw enables an attacker who has already gained master key access to the Parse Server instance to inject arbitrary SQL commands. The vulnerability stems from insufficient validation of field names used within the aggregate `$group` pipeline stage or the `distinct` operation. By injecting SQL metacharacters into these field names, an attacker can bypass intended restrictions and execute unauthorized database operations. This vulnerability specifically affects Parse Server deployments using PostgreSQL and does not impact those utilizing MongoDB. Successful exploitation leads to privilege escalation, granting the attacker PostgreSQL database-level access, potentially compromising sensitive data and system integrity.

## Attack Chain

1. Attacker gains master key access to the Parse Server application, potentially through credential compromise or vulnerability exploitation in another part of the application.
2. The attacker crafts a malicious API request targeting either the aggregate `$group` pipeline stage or the `distinct` operation.
3. The crafted API request includes SQL metacharacters embedded within the field name parameters of the `$group._id` object or the `distinct` dot-notation parameters.
4. Parse Server receives the request and, due to insufficient validation, passes the tainted field names to the PostgreSQL storage adapter.
5. The PostgreSQL storage adapter uses the tainted field names in a `:raw` interpolation when constructing the SQL query.
6. The injected SQL metacharacters are interpreted by the PostgreSQL database, altering the intended query logic.
7. The attacker executes arbitrary SQL commands, such as creating new users with elevated privileges or dumping sensitive data.
8. The attacker successfully escalates privileges from Parse Server application-level administrator to PostgreSQL database-level access, allowing for full control of the database.

## Impact

Successful exploitation of this SQL injection vulnerability allows an attacker to escalate privileges from a Parse Server administrator to a PostgreSQL database administrator. This could lead to the complete compromise of the database, including unauthorized access to sensitive data, modification of existing data, and denial of service. The vulnerability affects Parse Server deployments using PostgreSQL, potentially impacting any organization using vulnerable versions. Given the nature of Parse Server as a backend for mobile and web applications, a successful attack could expose user data and application logic, leading to significant financial and reputational damage.

## Recommendation

*   Upgrade Parse Server to version 8.6.59 or greater, or version 9.6.0-alpha.53 or greater, to patch CVE-2026-33539.
*   Implement input validation on the server side to sanitize field names before they are passed to the PostgreSQL adapter. While a full fix should be deployed, this provides defense in depth.
*   Monitor PostgreSQL logs for suspicious queries that contain unexpected SQL metacharacters in field names. Adapt the provided Sigma rule `Detect Suspicious Parse Server PostgreSQL Queries` to your logging environment.
