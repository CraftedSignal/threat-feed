---
title: Dgraph Pre-Auth DQL Injection Vulnerability
slug: 2024-10-dgraph-dql-injection
description: A pre-authentication DQL injection vulnerability in Dgraph's `/mutate` endpoint, when ACL is disabled, allows attackers to exfiltrate the entire database by crafting a malicious `cond` field in an upsert mutation.
date: "2024-10-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - dgraph
  - dql-injection
  - injection
  - database-exfiltration
vendors:
  - Dgraph
products:
  - Dgraph
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-mrxx-39g5-ph77
rules:
  - title: Detect Dgraph DQL Injection in Mutation Endpoint
    description: Detects potential DQL injection attempts in the Dgraph /mutate endpoint by looking for suspicious DQL syntax within the 'cond' field of the request body.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 1
---

A critical vulnerability exists in Dgraph, a graph database, allowing unauthenticated attackers to perform full database exfiltration. This flaw resides within the `/mutate` endpoint, specifically when Access Control Lists (ACL) are disabled, which is the default configuration. By injecting malicious DQL queries via a crafted `cond` field in an upsert mutation, attackers can bypass authorization checks and extract sensitive data, including user credentials and secrets. The vulnerability stems from the lack of proper sanitization of the `cond` field, leading to direct concatenation into the DQL query string. This vulnerability was found in v25.3.0, but may exist in other versions as well.

## Attack Chain

1. The attacker sends an HTTP POST request to the `/mutate?commitNow=true` endpoint without any authentication headers (e.g., `X-Dgraph-AccessToken`, `X-Dgraph-AuthToken`).
2. The `mutationHandler` in `http.go` extracts the request body and processes the `mutations` array, including the `cond` field, using `strconv.Unquote`.
3. The request proceeds to `edgraph.Server.QueryNoGrpc`, where the `Cond` value is copied verbatim to `dql.Mutation.Cond` in `server.go`.
4. The `buildUpsertQuery` function in `server.go` performs a simple string replacement (`@if` to `@filter`) but otherwise concatenates the unsanitized `Cond` value into the DQL query.
5. The `dql.ParseWithNeedVars` parser processes the constructed DQL string, accepting the injected query blocks as valid DQL.
6. The `authorizeQuery` function in `access.go` returns `nil` immediately because ACL is disabled (`AclSecretKey == nil`), bypassing authorization checks.
7. The injected query block executes, traversing and extracting data from the database.
8. The response, containing the exfiltrated data, is returned to the attacker via `http.go`, effectively granting unauthorized access to sensitive information.

## Impact

Successful exploitation of this vulnerability results in complete database exfiltration. Attackers can retrieve all nodes, predicates, and values within the Dgraph database, including sensitive data such as user credentials, API keys, and Personally Identifiable Information (PII). Given the default configuration of Dgraph lacking ACL enabled, this poses a significant risk to organizations relying on Dgraph for data storage. The injection can also manipulate upsert conditions, bypassing uniqueness constraints and conditional mutation logic.

## Recommendation

*   Enable ACL on all Dgraph instances and configure appropriate access controls to mitigate unauthorized data access.
*   Implement the Sigma rule `Detect Dgraph DQL Injection in Mutation Endpoint` to identify potentially malicious requests to the `/mutate` endpoint.
*   Sanitize and validate user-supplied input, especially the `cond` field in mutation requests, to prevent DQL injection attacks.
*   Monitor network traffic to detect suspicious POST requests to the `/mutate` endpoint with unusual or unexpected `cond` values.
*   Review and restrict network access to the Dgraph instance, limiting access only to authorized clients and networks.
