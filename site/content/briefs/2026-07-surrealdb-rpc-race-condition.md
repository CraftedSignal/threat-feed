---
title: SurrealDB HTTP RPC Session Race Condition Allows Privilege Escalation
slug: 2026-07-surrealdb-rpc-race-condition
description: An unauthenticated time-of-check/time-of-use (TOCTOU) race condition exists in the HTTP /rpc endpoint of SurrealDB versions prior to 3.1.0, allowing an attacker to inherit the session and privileges of an authenticated user by sending concurrent requests, potentially leading to full control over the database if a highly privileged session is hijacked.
date: "2026-07-03T12:35:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - race-condition
  - webserver
  - surrealdb
vendors:
  - SurrealDB
products:
  - SurrealDB (< 3.1.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An unauthenticated attacker who can reach the `/rpc` endpoint can escalate privileges by racing against any active authenticated session.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4vgr-h27g-cf9p
---

SurrealDB, a multi-model database, is affected by a critical time-of-check/time-of-use (TOCTOU) race condition (CVE-2024-XXXX, though not explicitly numbered in source) within its HTTP `/rpc` endpoint. This vulnerability impacts versions prior to `v3.1.0` and allows an unauthenticated attacker to escalate privileges. The flaw stems from concurrent requests sharing mutable authentication state; an unauthenticated request can race to inherit the session context of a legitimate, concurrently executing authenticated request. This mechanism, affecting the primary interface used by all official SurrealDB SDKs, allows attackers to bypass authentication and execute actions with the hijacked user's permissions, potentially leading to complete compromise of the SurrealDB instance if a root or namespace-level session is targeted.

## Attack Chain

1.  An authenticated user sends a legitimate `POST` request to the `/rpc` endpoint of a vulnerable SurrealDB instance.
2.  During the processing of this legitimate request, the server temporarily sets its internal, shared session state to the authenticated user's context.
3.  An unauthenticated attacker, with network access to the `/rpc` endpoint, concurrently sends a `POST` request to the same `/rpc` endpoint.
4.  Due to the TOCTOU race condition, the attacker's unauthenticated request is processed while the internal session state still holds the authenticated user's context.
5.  The attacker's request incorrectly inherits the session and privileges of the legitimate, authenticated user.
6.  The attacker's request is then executed with the elevated privileges of the hijacked session, bypassing authentication.
7.  If the hijacked session belonged to a root or namespace-level user, the attacker gains full control over the database, including reading, modifying, or deleting any data and creating persistent namespace-level users.
8.  If the hijacked session belonged to a scoped record user, the attacker's actions are limited to that user's defined permissions.

## Impact

An unauthenticated attacker exploiting this race condition can achieve privilege escalation within the SurrealDB instance. The severity of the impact is directly tied to the privileges of the authenticated user whose session is hijacked. If a highly privileged user, such as a root or namespace-level administrator, has their session compromised, the attacker can gain complete control over the database, including the ability to read, modify, or delete any data, as well as create new persistent users at the namespace level. This could lead to data integrity loss, unauthorized data access, and persistent compromise of the database environment.

## Recommendation

*   Upgrade SurrealDB instances to version `3.1.0` or newer immediately to apply the patch that introduces per-request session isolation.
*   Implement network-level controls (e.g., firewall rules, WAFs) to restrict access to the `/rpc` endpoint to only trusted clients and applications, reducing the exposure surface.
