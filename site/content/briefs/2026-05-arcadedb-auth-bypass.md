---
title: ArcadeDB Authorization Bypass Vulnerability
slug: 2026-05-arcadedb-auth-bypass
description: ArcadeDB versions prior to 26.4.2 are vulnerable to an authorization bypass, allowing authenticated users and API tokens scoped to a specific database to read, write, and mutate schema on any other database on the same server, and disabling the record-level authorization system for newly created databases.
date: "2026-05-05T22:22:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authorization bypass
  - privilege escalation
  - cve-2026-44221
vendors:
  - ArcadeData
products:
  - arcadedb-server
  - ArcadeDB
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-fxc7-fm93-6q77
  - https://github.com/ArcadeData/arcadedb/commit/04110c06315da55604ac107f71fe7182f3a3deb8
rules:
  - title: Detect ArcadeDB Database Access from Different IPs
    description: Detects access to multiple ArcadeDB databases from the same IP address within a short time frame, which may indicate an authorization bypass attempt.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect ArcadeDB Unsecured Database Creation
    description: Detects the creation of a new database via the API endpoint which may indicate an attempt to create an unsecured database.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

ArcadeDB, a multi-model database, is susceptible to an authorization bypass vulnerability affecting versions prior to 26.4.2. This vulnerability stems from two distinct defects: first, the `ServerSecurityUser.getDatabaseUser()` method returns a database user with an uninitialized file access map, which is then incorrectly interpreted as allowing all access. Second, the `ArcadeDBServer.createDatabase()` method omits the `factory.setSecurity(...)` call, effectively disabling the record-level authorization system for any database created via the API endpoint `POST /api/v1/server {"command":"create database X"}`.  This combination of flaws allows authenticated principals to bypass both record-level and database-level authorization constraints.

## Attack Chain

1. An attacker authenticates to the ArcadeDB server with valid credentials for a specific database.
2. The attacker leverages the `ServerSecurityUser.getDatabaseUser()` flaw to gain unauthorized access to other databases.
3. The attacker exploits the uninitialized `fileAccessMap` vulnerability, allowing them to bypass file access checks.
4. The attacker crafts a request to read data from a database they should not have access to, such as `GET /api/v1/database/OtherDatabase/query/sql/SELECT%20*%20FROM%20SomeTable`.
5. The server incorrectly authorizes the request due to the flawed access control mechanisms.
6. The attacker then attempts to modify the schema of another database using API calls that would normally be restricted based on database-level permissions. For example, `POST /api/v1/database/OtherDatabase {"command":"alter database X"}`.
7. If an attacker creates a new database using `POST /api/v1/server {"command":"create database X"}`, the record-level authorization system is disabled due to the missing `factory.setSecurity(...)` call.
8. The attacker then exploits the newly created database, which has no security checks, gaining complete control over its data and schema.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to sensitive data stored in other databases within the same ArcadeDB server. An attacker can read, write, and modify data across multiple databases, leading to potential data breaches, data corruption, and complete system compromise. Organizations using affected versions of ArcadeDB are at risk of significant data loss and reputational damage.  The vulnerability affects all deployments using versions prior to 26.4.2.

## Recommendation

*   Upgrade ArcadeDB server to version 26.4.2 to patch CVE-2026-44221 and resolve the authorization bypass vulnerability.
*   Monitor web server logs for unusual API requests targeting multiple databases from a single authenticated user to detect potential exploitation attempts, and deploy the provided Sigma rule `Detect ArcadeDB Database Access from Different IPs` to detect this activity.
*   Implement rate limiting on API endpoints to mitigate potential brute-force attacks aimed at exploiting this vulnerability and use `Detect ArcadeDB Unsecured Database Creation` Sigma rule to detect unauthorized database creation.
