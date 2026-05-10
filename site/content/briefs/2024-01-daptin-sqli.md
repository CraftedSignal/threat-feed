---
title: Daptin SQL Injection Vulnerability via Fuzzy Search
slug: 2024-01-daptin-sqli
description: Daptin versions up to 0.11.4 are vulnerable to SQL injection, where an authenticated user can inject unvalidated column names into raw SQL via the `processFuzzySearch` function, allowing them to read the entire database.
date: "2026-05-06T22:10:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sqli
  - daptin
  - github
  - fuzzy-search
products:
  - daptin/daptin
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
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-pwqg-q8pg-pp6r
rules:
  - title: Daptin Suspicious Fuzzy Search Query
    description: Detects suspicious requests to the Daptin API with 'fuzzy' operator and potential SQL injection attempts in the query parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Daptin User Account Signup Activity
    description: Detects Daptin User account signup attempts which can be a precursor to vulnerability exploitation.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Daptin versions up to and including 0.11.4 are susceptible to a SQL injection vulnerability within the `processFuzzySearch` function located in `server/resource/resource_findallpaginated.go`. This flaw allows any authenticated user, including those self-registered without administrative oversight, to inject arbitrary SQL commands by manipulating the `column` parameter during a fuzzy search. Specifically, when a GET request is made to `/api/<entity>` with the `operator` set to `fuzzy`, `fuzzy_any`, or `fuzzy_all`, the application fails to properly sanitize the column name before incorporating it into a raw SQL query. This vulnerability enables malicious actors to bypass column whitelists, potentially granting them unauthorized access to sensitive data within the entire database. The issue is distinct from the vulnerability patched in GHSA-rw2c-8rfq-gwfv and requires a separate patch to address the vulnerable fuzzy search path.

## Attack Chain

1.  An attacker registers a new user account, leveraging the default self-signup feature which requires no admin approval.
2.  The attacker authenticates with the newly created account to obtain a valid JWT (JSON Web Token).
3.  The attacker crafts a malicious HTTP GET request to `/api/<entity>`, setting the `operator` parameter to `fuzzy` (or `fuzzy_any`, `fuzzy_all`).
4.  The attacker injects a SQL payload into the `column` parameter using string formatting. For example: `reference_id) OR 1=1 OR LOWER(world.reference_id`.
5.  The crafted `column` parameter bypasses the column name whitelist check due to the execution path going through `processFuzzySearch` instead of `processQueryFilter`.
6.  The injected SQL payload is passed to `goqu.L`, which incorporates it directly into a raw SQL query without proper sanitization.
7.  The database executes the malicious SQL query, potentially leaking sensitive information or allowing for data manipulation.
8.  The attacker extracts data using boolean-blind SQL injection, exploiting the vulnerability to read data from all tables within the database, including credential data (emails, bcrypt password hashes) in the `user_account` table.

## Impact

Successful exploitation of this vulnerability allows an attacker with only a valid JWT to read the entire database via boolean-blind extraction. This includes sensitive information such as user credentials (emails and bcrypt password hashes). The self-signup feature of Daptin means that no administrative involvement is needed for an attacker to create an account and exploit this vulnerability.  The extraction rate is approximately 7 HTTP requests per character, making full database extraction feasible.

## Recommendation

*   Apply the patch that adds a `GetColumnByName` whitelist check in `processFuzzySearch` (line 1484) to prevent SQL injection via the `column` parameter.
*   Implement input validation and sanitization for the `column` parameter in the `processFuzzySearch` function to prevent the injection of arbitrary SQL commands.
*   Deploy the Sigma rule "Daptin Suspicious Fuzzy Search Query" to detect potential exploitation attempts based on the presence of SQL syntax in the `query` parameter of HTTP requests to the `/api/<entity>` endpoint.
*   Monitor web server logs (logsource: webserver) for requests to `/api/world` or other entities that include the `fuzzy` operator and contain suspicious characters or SQL syntax in the `query` parameter, as detected by the "Daptin Suspicious Fuzzy Search Query" rule.
