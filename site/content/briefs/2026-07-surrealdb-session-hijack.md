---
title: SurrealDB HTTP /rpc Session Hijack Vulnerability
slug: 2026-07-surrealdb-session-hijack
description: A critical vulnerability (versions prior to 3.1.0) in SurrealDB's HTTP /rpc endpoint allowed unauthenticated attackers to enumerate session UUIDs via the `sessions` method, enabling full session hijack of any attached and authenticated session due to a lack of ownership checks, leading to unauthorized data manipulation and privilege escalation.
date: "2026-07-03T12:36:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - surrealdb
  - vulnerability
  - session-hijack
  - web-application
  - rpc
  - database
vendors:
  - SurrealDB
products:
  - SurrealDB (< 3.1.0)
  - rust/surrealdb (< 3.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The HTTP `/rpc` `sessions` method returned every attached session UUID without authentication, and the `/rpc` handler accepted an arbitrary `session` field with no ownership check. An anonymous caller could enumerate UUIDs and impersonate any authenticated session.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An anonymous caller could enumerate UUIDs and impersonate any authenticated session.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: escalate to that session's privilege level (up to root).
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: an unauthenticated attacker can read, write, and delete any data the session can reach, dump metadata
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: execute arbitrary database operations (read, write, delete data)
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-5qfp-32cf-69jh
---

Anonymous attackers can exploit a critical vulnerability in SurrealDB’s HTTP `/rpc` endpoint, specifically affecting versions prior to 3.1.0. The flaw allows an unauthenticated caller to invoke the `sessions` method, which inadvertently returns all attached session UUIDs. Furthermore, the `/rpc` handler failed to perform ownership checks when a client-supplied session ID was present in a request. This combination enables an attacker to enumerate valid session identifiers and then impersonate any authenticated session by injecting a stolen UUID into subsequent requests. This vulnerability is particularly impactful for applications using the official Rust SDK’s `Http`/`Https` engine, as it automatically attaches sessions, making them enumerable and hijackable. Successful exploitation grants the attacker the full privileges of the hijacked session, including read, write, and delete capabilities over database data, as well as metadata exfiltration and privilege escalation.

## Attack Chain

1.  An anonymous attacker sends an unauthenticated HTTP GET or POST request to the SurrealDB `/rpc` endpoint, invoking the `sessions` method.
2.  The vulnerable SurrealDB server (versions < 3.1.0) responds to the unauthenticated request by returning a list of all currently attached session UUIDs.
3.  The attacker parses the server's response to extract one or more valid, potentially authenticated, session UUIDs.
4.  The attacker crafts a subsequent HTTP POST request to the `/rpc` endpoint, including a stolen session UUID within the `session` field of the request body or header.
5.  The vulnerable SurrealDB server processes this request without performing an ownership check, associating the incoming request with the privileges and context of the hijacked session.
6.  The attacker leverages the hijacked session's privileges to execute arbitrary database operations (e.g., read, write, or delete data), dump sensitive metadata, invalidate other sessions, or perform other actions commensurate with the compromised session's access level, potentially escalating to root.

## Impact

Successful exploitation allows an unauthenticated attacker to completely hijack any attached and authenticated SurrealDB session. This leads to unauthorized data access, modification, and deletion for any data the compromised session can reach. Attackers can also exfiltrate sensitive database metadata, invalidate legitimate user sessions, and achieve privilege escalation up to the highest level associated with the hijacked session, potentially gaining root access to the database. The breadth of impact depends directly on the privileges of the stolen session, posing a significant risk to data integrity, confidentiality, and availability for affected SurrealDB deployments.

## Recommendation

*   Upgrade all SurrealDB instances to version 3.1.0 or later immediately to patch the vulnerability described in this brief.
*   If immediate upgrade is not possible, modify application logic to avoid client flows that call `attach` against HTTP `/rpc`, as detailed in the workarounds section of this brief, prioritizing WebSocket transport or REST endpoints.
*   Implement network-level access controls to restrict direct access to the `/rpc` endpoint to only trusted internal clients, as described in the workaround for this vulnerability.
