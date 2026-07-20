---
title: SurrealDB Denial of Service Vulnerability (CVE-2026-63747)
slug: 2026-07-surrealdb-dos
description: SurrealDB versions prior to 3.1.0 contain a denial of service vulnerability in the RPC use handler that panics when the 'db' parameter is set without a corresponding namespace, allowing unauthenticated attackers to crash the server by sending a malformed WebSocket message to the /rpc endpoint.
date: "2026-07-20T12:26:29Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - web-application
  - database
vendors:
  - SurrealDB
products:
  - SurrealDB < 3.1.0
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: SurrealDB versions before 3.1.0 contain a denial of service vulnerability...Unauthenticated attackers can send a malformed WebSocket message to the /rpc endpoint to crash the server process.
    confidence_band: high
cves:
  - id: CVE-2026-63747
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63747
  - https://github.com/surrealdb/surrealdb/security/advisories/GHSA-wjjj-24cx-f28g
  - https://www.vulncheck.com/advisories/surrealdb-before-denial-of-service-via-malformed-rpc-use
---

SurrealDB, a popular next-gen database, versions prior to 3.1.0 are affected by a denial of service vulnerability, identified as CVE-2026-63747. This flaw resides in the Remote Procedure Call (RPC) use handler, specifically when it processes requests where the 'db' parameter is provided without a corresponding 'namespace' parameter. An unauthenticated attacker can exploit this condition by crafting and sending a malformed WebSocket message to the `/rpc` endpoint of a vulnerable SurrealDB instance. Upon receiving and attempting to process this malformed message, the RPC use handler triggers an unhandled panic, leading to the immediate termination and crash of the SurrealDB server process. This vulnerability allows for straightforward disruption of service without requiring authentication, posing a significant availability risk to organizations utilizing affected SurrealDB versions.

## Attack Chain

1. An unauthenticated attacker identifies a public-facing SurrealDB instance.
2. The attacker establishes a WebSocket connection to the `/rpc` endpoint on the vulnerable SurrealDB server.
3. The attacker crafts and sends a malformed WebSocket message to the `/rpc` endpoint.
4. The malformed message includes a 'db' parameter but omits the necessary 'namespace' parameter, creating an invalid state.
5. The SurrealDB RPC use handler receives and attempts to parse this malformed message.
6. Due to the specific malformation (db without namespace), the RPC handler encounters an unhandled exception or "panic".
7. This panic causes the entire SurrealDB server process to crash, resulting in a denial of service for all connected clients and applications.

## Impact

Successful exploitation of CVE-2026-63747 leads to a complete denial of service for the affected SurrealDB instance. An unauthenticated attacker can repeatedly crash the server, making the database unavailable to legitimate users and applications. This can severely disrupt operations for any organization relying on SurrealDB, leading to data unavailability, application downtime, and potential financial losses. The NVD assessed this vulnerability with a CVSS v3.1 base score of 7.5, classifying it as high severity due to its network-exploitability and complete impact on availability without requiring privileges.

## Recommendation

* Upgrade SurrealDB instances to version 3.1.0 or later immediately to patch CVE-2026-63747.
* Monitor network traffic for unusual WebSocket connection attempts or malformed requests directed at the `/rpc` endpoint of SurrealDB servers, which could indicate exploitation attempts for CVE-2026-63747.
