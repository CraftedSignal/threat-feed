---
title: Dgraph Pre-Auth Full Database Exfiltration via DQL Injection
slug: 2024-01-dgraph-dql-injection
description: A pre-authentication DQL injection vulnerability in Dgraph's default configuration allows attackers to exfiltrate the entire database by crafting malicious JSON mutations to the `/mutate` endpoint, exploiting unsanitized language tags in predicates.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - dgraph
  - dql-injection
  - vulnerability
vendors:
  - Dgraph
products:
  - Dgraph
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
references:
  - https://github.com/advisories/GHSA-x92x-px7w-4gx4
rules:
  - title: Detect Dgraph DQL Injection Attempt via Mutate Endpoint
    description: Detects potential DQL injection attacks against Dgraph by identifying suspicious characters or patterns within the predicate name in HTTP POST requests to the /mutate endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Dgraph Alter Schema with Lang Directive
    description: Detects attempts to add a schema with the @lang directive via the /alter endpoint, which is a prerequisite for the DQL injection vulnerability.
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

A critical vulnerability in Dgraph, specifically within the `addQueryIfUnique` function, enables unauthenticated attackers to perform full database exfiltration. This affects default configurations where Access Control Lists (ACLs) are disabled. The attack involves sending crafted HTTP POST requests to the `/alter` and `/mutate` endpoints on port 8080. The vulnerability stems from the lack of sanitization of the `Lang` field in JSON mutations, which allows for DQL injection. By exploiting the `x.PredicateLang()` function, which splits predicate names on `@`, attackers can inject malicious code into the language tag. This injected code allows attackers to execute arbitrary DQL queries, bypassing authentication mechanisms and extracting sensitive data from the database. This vulnerability was tested on Dgraph version v25.3.0, posing a significant risk to organizations using Dgraph with default settings.

## Attack Chain

1. The attacker sends an HTTP POST request to the `/alter` endpoint to create a schema predicate with `@unique @index(exact) @lang`. No authentication is required in the default Dgraph configuration.
2. The attacker crafts a JSON mutation containing a malicious payload. The key in the JSON mutation includes the predicate name followed by `@` and the DQL injection payload in the language tag position, such as `name@en,"x")) leak(func: has(dgraph.type)) { uid dgraph.type name email secret aws_access_key_id aws_secret_access_key } } #`.
3. The attacker sends the crafted JSON mutation via an HTTP POST request to the `/mutate?commitNow=true` endpoint.
4. The `mutationHandler` parses the JSON body and identifies the malicious predicate and language tag.
5. The `x.PredicateLang` function splits the key on the last `@`, separating the predicate and the injection payload.
6. The `addQueryIfUnique` function constructs a DQL query string by interpolating the raw language tag from the mutation into the query via `fmt.Sprintf` without any sanitization.
7. The constructed DQL is parsed, and the injected query is executed, bypassing authentication checks due to `AclSecretKey == nil`.
8. The results of the injected query, containing the entire database content, are returned to the attacker in the HTTP response.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to exfiltrate the entire Dgraph database, including all nodes, predicates, and values. This could lead to severe data breaches, exposure of sensitive information, and potential compromise of user credentials, API keys, or other confidential data stored within the database. The vulnerability affects Dgraph instances using the default configuration without ACL enabled, which poses a high risk to a wide range of deployments across various sectors.

## Recommendation

*   Deploy the following Sigma rule to detect DQL injection attempts by monitoring for unusual characters and patterns in the `predicateName` field (within application logs or network traffic capturing HTTP POST requests) to the `/mutate` endpoint.
*   Enable ACL in Dgraph to require authentication for `/alter` and `/mutate` endpoints, mitigating the pre-authentication aspect of the vulnerability.
*   Implement input validation and sanitization for the `Lang` field in JSON mutations to prevent DQL injection, focusing on the `x.PredicateLang` function and `addQueryIfUnique` function within `edgraph/server.go`.
