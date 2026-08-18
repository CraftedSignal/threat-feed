---
title: Authorization Bypass in ArcadeDB Gremlin Plugin
slug: 2026-08-arcadedb-auth-bypass
description: The ArcadeDB Gremlin wire-protocol plugin versions 26.7.3 and prior fail to perform authorization checks for authenticated users, allowing unauthorized cross-database data manipulation and ACL bypass.
date: "2026-08-18T14:54:20Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - ArcadeDB
products:
  - arcadedb-gremlin (<= 26.7.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: any valid server credential — even one provisioned for zero or one unrelated database — can read, write, and drop data in any database on the server, completely bypassing the engine's per-type/read-only/UPDATE_SCHEMA ACLs.
    confidence_band: high
cves:
  - id: CVE-2026-75853
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75853
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade arcadedb-gremlin to 26.8.1
      owner: IT Operations
      due: 72h
      evidence: The issue is fixed in version 26.8.1.
  hunt_leads:
    - lead: Log inspection for Gremlin queries traversing databases outside of assigned user scope
      technique_id: T1068
      data_needed:
        - Application logs
        - Database access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: the plugin... never checks database access permissions (canAccessToDatabase)
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 26.8.1
      owner: IT Operations
      addresses: CVE-2026-75853
      evidence: NVD vulnerability disclosure
---

The vulnerability (CVE-2026-75853) affects the arcadedb-gremlin plugin used by ArcadeDB versions 26.7.3 and earlier. While the plugin correctly implements SASL PLAIN authentication, it fails to enforce authorization logic. Specifically, the plugin does not invoke the check for database access permissions (canAccessToDatabase) and fails to bind the authenticated user to the database engine. Consequently, any user with valid server credentials can read, write, or drop data across any database hosted on the server. This bypasses all engine-level security controls, including per-type ACLs, read-only constraints, and schema update restrictions. The issue was resolved in version 26.8.1. Organizations running ArcadeDB with the Gremlin plugin enabled should prioritize upgrading to 26.8.1 to restore granular database access controls.

## Attack Chain

1. Attacker authenticates to the target ArcadeDB server using valid (potentially low-privileged) credentials via the Gremlin wire-protocol.
2. Attacker establishes a session using the SASL PLAIN authentication mechanism.
3. Attacker identifies a target database on the server, potentially one they are not authorized to access.
4. Attacker uses a traversal-source alias to reference the unauthorized target database within the Gremlin query structure.
5. The plugin processes the request without performing an authorization check against the database engine.
6. The underlying engine executes the request with the context of the authenticated session, ignoring the intended ACL boundaries.
7. Attacker performs unauthorized actions such as data exfiltration (read), modification (write), or data destruction (drop).

## Impact

Successful exploitation allows an attacker to bypass all database-level security restrictions. An attacker can gain unauthorized read/write/delete access to any database hosted on an instance where they possess valid credentials for at least one database. This impacts data confidentiality, integrity, and availability.

## Recommendation

- Upgrade the arcadedb-gremlin plugin to version 26.8.1 or later.
- Audit database access logs for unusual cross-database traversals or queries initiated by accounts that should not have scope over the entire server.
- Apply the principle of least privilege by restricting user credentials to the minimum necessary databases until patches are deployed.
