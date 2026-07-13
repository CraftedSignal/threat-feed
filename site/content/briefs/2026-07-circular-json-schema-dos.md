---
title: Circular JSON Schema $ref Causes Unbounded CPU DoS in json_repair Library
slug: 2026-07-circular-json-schema-dos
description: An unbounded CPU Denial-of-Service vulnerability exists in the `json_repair` library's `SchemaRepairer.resolve_schema()` function, allowing an unauthenticated attacker to provide a specially crafted JSON schema containing a circular `$ref` pointer, leading to indefinite CPU consumption and service unavailability.
date: "2026-07-13T23:43:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - supply-chain
  - application-vulnerability
  - python
vendors:
  - mangiucugna
products:
  - json_repair (< 0.60.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker who can supply a schema containing a self-referencing `$ref` (e.g., via the demo Flask API or any application that passes untrusted input to `loads(..., schema=...)`), can cause a worker process to spin indefinitely on CPU, resulting in a complete denial of service.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xf7x-x43h-rpqh
---

An unauthenticated attacker can exploit a critical flaw in the `json_repair` library (versions prior to `0.60.1`) to trigger a Denial of Service (DoS) condition. The vulnerability resides in the `SchemaRepairer.resolve_schema()` function, which is responsible for processing JSON schema `$ref` pointers. This function lacks cycle detection, meaning that if an attacker supplies a schema containing a self-referencing `$ref` (e.g., `{"$ref": "#/definitions/a", "definitions": {"a": {"$ref": "#/definitions/a"}}}`), the library enters an infinite loop. This unbounded CPU consumption by the worker process effectively halts the service, making it unavailable to other users. The vulnerability is reproducible and has been assigned a high severity CVSS score of 7.5. Applications that pass untrusted input to `json_repair.loads(..., schema=...)`, including the library's public demo Flask API, are susceptible.

## Attack Chain

1. An unauthenticated attacker sends an HTTP POST request to a web application endpoint (e.g., `/api/repair-json` in the demo Flask API) that accepts user-controlled JSON input.
2. The request body contains a specially crafted JSON payload that includes a `schema` field with a circular `$ref` definition, such as `{"$ref": "#/definitions/a", "definitions": {"a": {"$ref": "#/definitions/a"}}}`.
3. The vulnerable application extracts the user-provided `schema` from the HTTP request body and passes it directly to the `json_repair.loads()` function for processing.
4. Internally, `json_repair.loads()` instantiates a `SchemaRepairer` object and calls its `is_valid()` method, which subsequently invokes the `SchemaRepairer.resolve_schema()` function.
5. Within `SchemaRepairer.resolve_schema()`, a `while` loop attempts to resolve the `$ref` chain without any cycle detection. Due to the circular `$ref`, the internal `_resolve_ref()` function continuously returns the same dictionary object.
6. The `while` loop never terminates, leading to an unbounded consumption of CPU resources by the application's worker process.
7. This indefinite CPU spin causes the affected worker process to hang indefinitely, making the application unresponsive and inaccessible.
8. The consequence is a complete Denial of Service for other legitimate users attempting to access the service.

## Impact

This vulnerability results in an unauthenticated denial-of-service condition affecting any application that utilizes the `json_repair` library and exposes `json_repair.loads(..., schema=<user-controlled>)` to untrusted input. A single malicious HTTP request carrying a circular `$ref` schema can cause a Flask worker process (or similar) to consume CPU indefinitely. This makes the service unresponsive and unavailable, requiring manual intervention such as killing the hung process or restarting the server. The attack requires no special privileges and deterministically reproduces the service disruption, though it does not affect data confidentiality or integrity.

## Recommendation

* Patch the `json_repair` library to version `0.60.1` or higher immediately to address the identified vulnerability.
* Implement strict input validation and sanitize all user-supplied JSON schemas before passing them to `json_repair.loads()` with the `schema` parameter, specifically checking for circular `$ref` definitions to prevent the infinite loop.
