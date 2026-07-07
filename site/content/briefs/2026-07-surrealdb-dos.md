---
title: SurrealDB Denial of Service Vulnerability via JSON Parser (GHSA-q729-696q-g9pq)
slug: 2026-07-surrealdb-dos
description: An unauthenticated remote attacker can exploit a Denial of Service vulnerability (GHSA-q729-696q-g9pq) in SurrealDB's value and JSON parser, which failed to enforce recursion depth limits when processing deeply nested JSON payloads sent to the WebSocket /rpc endpoint, leading to server memory exhaustion and process crashes.
date: "2026-07-03T12:29:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - websocket
  - server
vendors:
  - SurrealDB
products:
  - SurrealDB (< 3.1.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker can crash a SurrealDB server with a single WebSocket message.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-q729-696q-g9pq
  - https://github.com/surrealdb/surrealdb/security/advisories/GHSA-6r8p-hpg7-825g
---

A high-severity Denial of Service vulnerability (GHSA-q729-696q-g9pq) has been identified in SurrealDB, affecting versions prior to 3.1.0. An unauthenticated remote attacker can exploit this flaw by sending a specially crafted, deeply nested JSON payload to the server's WebSocket `/rpc` endpoint. The vulnerability lies in the value and JSON parser, which inconsistently failed to enforce configured recursion depth limits for nested objects, arrays, or parentheses. This oversight allows the malicious payload to exhaust server memory during parsing, leading to the immediate crash of the SurrealDB process. This issue is a partial fix for a previous vulnerability (GHSA-6r8p-hpg7-825g) that addressed a similar problem in the expression parser but overlooked the value/JSON parser code path. The immediate impact is service unavailability for affected SurrealDB instances, requiring manual restart.

## Attack Chain

1.  **Reconnaissance**: An attacker identifies a publicly exposed SurrealDB instance, potentially through port scanning or misconfiguration.
2.  **Vulnerability Identification**: The attacker identifies the accessible WebSocket `/rpc` endpoint, which is vulnerable to unauthenticated input.
3.  **Payload Crafting**: The attacker crafts a malicious JSON payload characterized by extremely deep nesting of objects (`{}`), arrays (`[]`), or parentheses (`()`).
4.  **Connection Establishment**: The attacker establishes a WebSocket connection to the identified `/rpc` endpoint on the vulnerable SurrealDB server.
5.  **Malicious Request**: The crafted, deeply nested JSON payload is sent by the attacker over the established WebSocket connection to the SurrealDB server.
6.  **Vulnerable Parsing**: The SurrealDB server's value and JSON parser attempts to process the incoming payload but fails to enforce its configured recursion depth limits due to the identified vulnerability.
7.  **Resource Exhaustion**: The uncontrolled recursive parsing of the deeply nested JSON payload rapidly consumes and exhausts the server's available memory resources.
8.  **Denial of Service**: The SurrealDB process crashes as a result of the memory exhaustion, rendering the database service completely unavailable to legitimate users.

## Impact

The primary impact of this vulnerability is a complete Denial of Service for affected SurrealDB instances. An unauthenticated remote attacker can trigger a server crash with a single malicious WebSocket message, requiring no prior credentials or query execution privileges. This vulnerability can lead to significant downtime for any applications or services relying on the SurrealDB instance, causing operational disruption and potential data inconsistencies if the server crashes unexpectedly during write operations. There are no known workarounds other than restricting network access or patching.

## Recommendation

*   **Patch CVE-GHSA-q729-696q-g9pq immediately**: Upgrade all SurrealDB instances to version 3.1.0 or later to apply the fix for this vulnerability.
*   **Restrict Network Access**: Implement network access controls (firewalls, security groups) to restrict access to the WebSocket `/rpc` endpoint to only trusted clients or internal networks.
