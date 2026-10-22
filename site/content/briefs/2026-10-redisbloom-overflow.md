---
brief_id: brief-2026-10-22-redisbloom-overflow
event_id: brief-2026-10-22-redisbloom-overflow
revision: 1
activity_at: "2026-10-22T12:49:48Z"
title: 'RedisBloom and Redis OSS: Count-Min Sketch RDB deserialization integer overflow (CVE-2026-62356)'
slug: 2026-10-redisbloom-overflow
description: An integer-overflow vulnerability in RedisBloom CMSketch RDB deserialization allows an authenticated attacker to trigger out-of-bounds memory access, resulting in potential remote code execution or denial of service.
date: "2026-10-22T12:49:48Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against RedisBloom security advisory and public exploit documentation.
tags:
  - redis
  - integer-overflow
  - rce
  - dos
vendors:
  - Redis
products:
  - Redis OSS (< 8.8.2)
  - RedisBloom (< 2.8.24)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An authenticated Redis client can load a specially crafted CMSketch object ... causing an undersized heap buffer to be accepted ... Any subsequent CMS command then indexes far out of bounds — a crash (DoS) at minimum
    confidence_band: high
cves:
  - id: CVE-2026-62356
    kev_status: unknown
references:
  - https://github.com/RedisBloom/RedisBloom/security/advisories/GHSA-q5p6-hwxh-c23h
  - https://sploitus.com/exploit?id=375DF200-1D6B-5FA8-8688-3F16234B3A15
  - https://sploitus.com/exploit?id=375DF200-1D6B-5FA8-8688-3F16234B3A15&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Redis OSS to 8.8.2+ and RedisBloom to 2.8.24+.
      owner: IT Operations
      due: 24h
      evidence: Upstream advisory specifies these versions as the fix.
    - action: Audit Redis ACLs to ensure RESTORE, MIGRATE, and DEBUG are restricted to highly trusted administrative identities.
      owner: SOC
      due: 48h
      evidence: Mitigation step provided in the RedisBloom advisory.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Redis OSS 8.8.2+ and RedisBloom 2.8.24+.
      owner: IT Operations
      addresses: CVE-2026-62356
      evidence: Upstream advisory
---

RedisBloom is vulnerable to an integer-overflow issue (CVE-2026-62356) within its Count-Min Sketch (CMSketch) RDB deserialization process. By providing a crafted CMSketch object through the `RESTORE` command or malicious RDB file ingestion, an authenticated attacker can cause the server to allocate an undersized heap buffer. Subsequent interaction with the sketch via commands such as `CMS.QUERY`, `CMS.INCRBY`, or `CMS.INFO` triggers out-of-bounds memory access. This behavior causes a crash (denial of service) or potential remote code execution. A non-weaponized proof-of-concept demonstrating the denial-of-service condition is publicly available.

## Attack Chain
1. Attacker authenticates to the Redis instance.
2. Attacker crafts a malicious CMSketch object with dimensions designed to induce integer overflow in the length computation.
3. Attacker sends the payload to the target via `RESTORE` or triggers ingestion of a compromised RDB file.
4. The server's `CMSRdbLoad` routine performs a 64-bit length calculation that wraps around, resulting in the allocation of an undersized heap buffer.
5. The server commits the poisoned CMSketch object to memory.
6. Attacker invokes CMS commands (`CMS.QUERY`, `CMS.INCRBY`, `CMS.INFO`) on the object.
7. The server calculates an index based on the corrupted object dimensions and performs an out-of-bounds access on the undersized heap buffer, leading to SIGSEGV/crash or potential arbitrary code execution.

## Impact
Successful exploitation allows for persistent denial-of-service (the corrupted object remains in memory across restarts if persisted to RDB) and provides a primitive for potential remote code execution in the context of the Redis server process.

## Recommendation
1. Patch immediately by upgrading to Redis OSS 8.8.2 or later, and RedisBloom 2.8.24 or later.
2. If an immediate upgrade is not feasible, restrict access to `RESTORE`, `MIGRATE`, `DEBUG`, and RDB ingestion commands via Redis ACLs to trusted users only.
3. Treat all serialized data import pathways, including replication, RDB preloading, and backup restoration, as high-risk vectors.
