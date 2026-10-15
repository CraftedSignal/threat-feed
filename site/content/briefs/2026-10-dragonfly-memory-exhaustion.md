---
title: Unbounded Memory Allocation in DragonflyDB
slug: 2026-10-dragonfly-memory-exhaustion
description: An unauthenticated denial-of-service vulnerability in DragonflyDB allows remote attackers to cause instance termination via unbounded memory allocation.
date: "2026-10-15T22:49:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:dragonflydb:dragonfly:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - dragonflydb
vendors:
  - DragonflyDB
products:
  - Dragonfly (<= 2.0.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can send a single command against a one-element key with a huge negative COUNT to trigger the OOM killer, terminating the instance for all clients.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111279
---

DragonflyDB versions 2.0.2 and earlier contain an unbounded memory allocation vulnerability identified as CVE-2026-111279. The flaw exists in the handling of the COUNT argument within the HRANDFIELD, ZRANDMEMBER, and SRANDMEMBER commands. An unauthenticated attacker can exploit this by sending a specially crafted command featuring a large negative COUNT value against a key containing a single element. This triggers the server to allocate an excessive amount of memory, forcing the operating system to invoke the Out-of-Memory (OOM) killer. The resulting memory pressure leads to the termination of the Dragonfly instance, causing a complete denial-of-service for all connected clients. Given the ease of exploitation through a single command, this vulnerability presents a significant risk to the availability of affected deployments.

## Impact

Successful exploitation of CVE-2026-111279 results in the immediate termination of the DragonflyDB instance. This causes a denial-of-service condition, disrupting all services dependent on the database. Because the attack only requires a single command to a key with at least one element, the barrier to exploitation is low for any network-reachable instance.

## Recommendation

- Upgrade all instances of DragonflyDB to a version beyond 2.0.2 that addresses the memory allocation flaw.
- Restrict network access to DragonflyDB instances to authorized clients only, preventing unauthenticated access to the service.
