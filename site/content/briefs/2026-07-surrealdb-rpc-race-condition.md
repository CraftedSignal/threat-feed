---
title: SurrealDB RPC Endpoint Race Condition Allows Privilege Escalation (CVE-2026-63756)
slug: 2026-07-surrealdb-rpc-race-condition
description: SurrealDB versions before 3.1.0 contain a time-of-check/time-of-use (TOCTOU) race condition in the HTTP /rpc endpoint that allows unauthenticated attackers to hijack authenticated session state and execute operations with elevated user privileges, leading to privilege escalation.
date: "2026-07-20T12:27:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - race-condition
  - privilege-escalation
  - web-application
  - vulnerability
vendors:
  - SurrealDB
products:
  - SurrealDB (< 3.1.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Unauthenticated attackers can send concurrent requests to the /rpc endpoint while legitimate authenticated traffic is active to execute operations with hijacked user privileges.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SurrealDB versions before 3.1.0 contain a time-of-check/time-of-use race condition in the HTTP /rpc endpoint that allows unauthenticated requests to inherit authenticated session state.
    confidence_band: high
cves:
  - id: CVE-2026-63756
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63756
  - https://github.com/surrealdb/surrealdb/security/advisories/GHSA-4vgr-h27g-cf9p
  - https://www.vulncheck.com/advisories/surrealdb-before-privilege-escalation-via-rpc-session-race-condition
---

CVE-2026-63756 describes a critical time-of-check/time-of-use (TOCTOU) race condition vulnerability affecting SurrealDB versions prior to 3.1.0. This flaw resides within the HTTP /rpc endpoint, enabling unauthenticated attackers to exploit a timing window. By sending concurrent requests to this endpoint while legitimate authenticated users are active, an attacker can cause their unauthenticated requests to inherit the session state of an authenticated user. This session hijacking allows the attacker to perform actions with the privileges of the compromised user, effectively leading to privilege escalation within the SurrealDB instance. The vulnerability has a CVSS v3.1 base score of 8.1 (High severity), indicating a significant risk for organizations using vulnerable versions of SurrealDB.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable SurrealDB instance running a version prior to 3.1.0.
2. The attacker monitors for active, legitimate user sessions to the HTTP /rpc endpoint.
3. The attacker sends a crafted unauthenticated request to the /rpc endpoint.
4. Concurrently, the attacker rapidly sends additional requests to the same /rpc endpoint, attempting to coincide with the execution flow of an authenticated user's request.
5. Due to the TOCTOU race condition, one of the attacker's requests is processed within the context of an authenticated session.
6. The attacker's request inherits the authenticated session state, allowing them to execute operations with the hijacked user's privileges.
7. The attacker performs unauthorized actions, such as data manipulation, unauthorized access, or further privilege escalation.

## Impact

Successful exploitation of CVE-2026-63756 can lead to severe consequences for organizations using vulnerable SurrealDB instances. An attacker gaining hijacked user privileges can perform any action that the compromised legitimate user is authorized to do. This includes, but is not limited to, accessing sensitive data, modifying database records, deleting critical information, or manipulating system configurations, potentially leading to data breaches, data integrity issues, or complete system compromise. The impact is significant as it allows unauthenticated remote attackers to gain high privileges within the database.

## Recommendation

* Patch CVE-2026-63756 immediately by upgrading all SurrealDB instances to version 3.1.0 or later.
* Implement robust monitoring of HTTP /rpc endpoint access for SurrealDB instances, looking for unusual patterns of concurrent requests from unauthenticated or unknown sources.
* Review web application firewall (WAF) rules to identify and potentially block suspicious traffic patterns targeting the /rpc endpoint, especially high volumes of concurrent requests.
