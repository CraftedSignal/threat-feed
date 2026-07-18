---
title: SurrealDB RPC API Arbitrary Object Execution Vulnerability
slug: 2026-07-surrealdb-rpc-arbitrary-object-execution
description: An unauthenticated remote code execution vulnerability exists in SurrealDB's RPC API, affecting versions prior to 1.5.5 and 2.0.0-beta prior to 2.0.0-beta.3, allowing attackers to inject a specially crafted binary object containing a subquery during signin or signup operations, leading to execution with editor-level privileges and manipulation of non-IAM database resources.
date: "2026-07-18T14:20:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - database-vulnerability
  - remote-code-execution
  - unauthenticated-access
  - data-manipulation
vendors:
  - SurrealDB
products:
  - SurrealDB (< 1.5.5)
  - SurrealDB (2.0.0-beta < 2.0.0-beta.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: When a record access method defines a SIGNIN or SIGNUP query and the RPC API is exposed to untrusted users, an unauthenticated attacker can encode a binary object containing a subquery using the bincode serialization format and supply it in place of credentials.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The subquery is then executed within the database owner's SIGNIN/SIGNUP query under a system user session with the editor role
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: allowing the attacker to select, create, update, and delete non-IAM resources
    confidence_band: high
cves:
  - id: CVE-2024-58362
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-58362
---

CVE-2024-58362 describes a high-severity vulnerability in SurrealDB versions before 1.5.5 and 2.0.0-beta before 2.0.0-beta.3. This flaw allows an unauthenticated attacker to execute arbitrary subqueries within the database. The vulnerability arises because the SurrealDB RPC API's `signin` and `signup` operations accept an arbitrary object without proper recursive validation for non-computed values. When the RPC API is exposed to untrusted users and a record access method defines a `SIGNIN` or `SIGNUP` query, an attacker can embed a malicious subquery within a binary object using the bincode serialization format. This crafted object is then supplied in place of legitimate credentials, and the subquery is executed under a system user session with an `editor` role. This grants the attacker the ability to select, create, update, and delete non-IAM resources within the database, posing a significant risk to data integrity and confidentiality.

## Attack Chain

1. An unauthenticated attacker identifies an exposed SurrealDB RPC API instance in a target environment.
2. The attacker determines that a record access method defines a `SIGNIN` or `SIGNUP` query, making the vulnerability exploitable.
3. The attacker crafts a binary object that leverages the bincode serialization format to embed a malicious subquery.
4. The attacker sends this specially crafted binary object as part of a `signin` or `signup` operation to the vulnerable RPC API endpoint.
5. SurrealDB's RPC API processes the arbitrary object without proper recursive validation of non-computed values, leading to the acceptance and processing of the malicious subquery.
6. The embedded subquery is executed within the database owner's `SIGNIN`/`SIGNUP` query context.
7. The subquery runs under a system user session, inheriting an `editor` role, and performs unauthorized actions.
8. The attacker's subquery successfully selects, creates, updates, or deletes non-IAM resources within the SurrealDB database, achieving unauthorized data manipulation.

## Impact

Successful exploitation of CVE-2024-58362 allows an unauthenticated attacker to gain significant control over the SurrealDB database's non-IAM resources. Attackers can execute arbitrary subqueries, leading to unauthorized selection, creation, modification, or deletion of data. This could result in data theft, data corruption, or the complete compromise of information stored within the database. While the attacker cannot directly view the results of the query or affect IAM resources (which require an 'owner' role), the ability to manipulate core database content at an 'editor' level presents a critical risk to data integrity and confidentiality.

## Recommendation

* **Patch CVE-2024-58362 immediately** by upgrading SurrealDB to version 1.5.5 or later, or 2.0.0-beta.3 or later, to remediate the arbitrary object execution vulnerability.
* Restrict network exposure of the SurrealDB RPC API to trusted users and internal networks only, preventing untrusted users from accessing vulnerable endpoints.
* Monitor SurrealDB RPC API logs for unusual `signin` or `signup` requests originating from suspicious IP addresses or containing abnormally large or malformed payloads, as these could indicate an attempted exploitation of CVE-2024-58362.
