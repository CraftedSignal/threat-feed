---
title: Unauthenticated Remote Data Replacement in Dgraph Alpha
slug: 2026-08-dgraph-snapshot-unauth
description: An unauthenticated remote attacker can leverage the Dgraph Alpha gRPC interface to clear or replace internal database group stores, potentially leading to unauthorized data modification and privilege escalation.
date: "2026-08-20T19:12:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Dgraph
products:
  - Dgraph
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker who can reach Alpha's public gRPC port can clear a selected Dgraph group store.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: This operation deletes and replaces the existing DB data.
    confidence_band: high
cves:
  - id: CVE-2026-54061
    cvss: 9.1
    epss: 0.00388
references:
  - https://github.com/advisories/GHSA-rrwh-6jrq-wp5v
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block inbound traffic to Dgraph gRPC port :9080 from untrusted network segments.
      owner: IT Operations
      due: 24h
      evidence: The RPCs used for external snapshot import are exposed through Alpha’s public gRPC service.
  hunt_leads:
    - lead: Identify unauthorized gRPC connections to Dgraph Alpha instances targeting the StreamExtSnapshot method.
      technique_id: T1190
      data_needed:
        - Network flow logs or gRPC application logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An unauthenticated network client can open StreamExtSnapshot and send Badger stream data.
  mitigation_plan:
    - priority: immediate
      action: Enforce mTLS and network-level authentication for all gRPC services.
      owner: IT Operations
      addresses: CVE-2026-54061
      evidence: Public gRPC mTLS is not enabled.
---

Dgraph Alpha versions 25.3.4 and earlier are vulnerable to an unauthenticated remote code execution and data manipulation flaw due to improper access control in its public gRPC interface (port :9080). The service exposes the `StreamExtSnapshot` method without requiring authentication, authorization, or mTLS. Because the server-side implementation calls `StreamWriter.Prepare()` before processing incoming data streams, an unauthenticated client can trigger the immediate deletion of an existing database group store. Attackers can leverage this to clear production data or replace the group store with arbitrary Badger stream data. This vulnerability is particularly dangerous when targeting Group 1, which houses internal ACL and predicate information, as the ability to inject custom data here facilitates unauthorized privilege escalation within the Dgraph cluster.

## Attack Chain

1. Attacker identifies a Dgraph Alpha instance reachable over the network on port :9080.
2. Attacker establishes a standard gRPC connection to the target without providing a JWT, ACL token, or auth-token metadata.
3. Attacker invokes the `Dgraph.StreamExtSnapshot` RPC method against a specific group ID (e.g., Group 1).
4. The Dgraph server fails to validate the requester's authorization context, accepting the stream request.
5. The server-side logic triggers `worker.runLocalSubscriber` and subsequently calls `pstore.NewStreamWriter().Prepare()`.
6. The target group's database is purged by the Dgraph engine as part of the `Prepare()` operation.
7. Attacker sends a stream packet with a `Done` flag, or alternatively, streams valid Badger data chunks to overwrite the store.
8. Final objective achieved: targeted database contents are replaced with attacker-controlled data, causing potential privilege escalation or service disruption.

## Impact

Successful exploitation allows for the complete removal of existing data or the substitution of database contents with malicious payloads. By overwriting the database group responsible for access control (Group 1), an attacker can inject rogue administrative accounts or modify ACL settings to grant themselves elevated privileges, compromising the integrity and security of the entire Dgraph cluster.

## Recommendation

1. Immediately restrict network access to Dgraph gRPC port :9080, ensuring it is not exposed to the public internet or untrusted networks.
2. Upgrade all Dgraph Alpha instances to a patched version beyond 25.3.4 once available from the vendor.
3. Enforce mTLS for all gRPC communications to ensure only authorized clients can interact with the Alpha service.
4. Review database group 1 for unauthorized changes or unexpected ACL modifications that may indicate exploitation of this vulnerability.
