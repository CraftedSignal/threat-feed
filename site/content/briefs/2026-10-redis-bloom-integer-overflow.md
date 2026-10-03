---
title: Remote Code Execution via Integer Overflow in RedisBloom Module
slug: 2026-10-redis-bloom-integer-overflow
description: An integer overflow vulnerability (CVE-2024-55656) in the RedisBloom module's CMS.INITBYDIM command enables heap underallocation, allowing authenticated attackers to perform out-of-bounds memory operations and achieve remote code execution.
date: "2026-10-03T17:01:06Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - rick2600
tags:
  - redis
  - cve
  - rce
  - memory-corruption
vendors:
  - Redis
products:
  - RedisBloom (< 2.6.12)
  - Redis Stack (7.2.0-v10)
  - Redis (< 6.2.17)
  - Redis (7.2.7)
  - Redis (7.4.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: This integer overflow vulnerability enables remote code execution.
    confidence_band: high
cves:
  - id: CVE-2024-55656
    cvss: 8.8
    epss: 0.15009
references:
  - https://www.zerodayinitiative.com/advisories/ZDI-25-009/
  - https://github.com/RedisBloom/RedisBloom/security/advisories/GHSA-x5rx-rmq3-ff3h
  - https://redis.io/blog/security-advisory-cve-2024-46981-cve-2024-51737-cve-2024-51480-cve-2024-55656/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch RedisBloom to 2.2.19 or later
      owner: IT Operations
      due: 48h
      evidence: Vendor security advisory documentation.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to Redis port 6379.
      owner: Security Operations
      addresses: CVE-2024-55656
      evidence: General security hardening guidance.
---

CVE-2024-55656 is an integer overflow vulnerability affecting the RedisBloom module, specifically versions including v2.6.12 as found in Redis Stack 7.2.0-v10. The vulnerability resides in the CMS.INITBYDIM command, which initializes a Count-Min Sketch. By providing manipulated width and depth parameters, an attacker can cause an integer overflow during memory calculation, resulting in a heap buffer underallocation. Because the system allocates less memory than required, subsequent calls to CMS.QUERY (for out-of-bounds reading) or CMS.INCRBY (for out-of-bounds writing) allow for memory corruption, potential information disclosure, and ultimately, arbitrary code execution. This vulnerability requires the attacker to be authenticated to the Redis instance. Defenders should prioritize patching RedisBloom modules and monitoring for abnormal parameter values passed to CMS-related commands.

## Attack Chain

1. Attacker establishes an authenticated session with a target Redis instance.
2. Attacker identifies a Redis server running a vulnerable version of the RedisBloom module.
3. Attacker constructs a malicious CMS.INITBYDIM command with extreme width and depth parameters.
4. The module's NewCMSketch function performs an insecure multiplication of these parameters, leading to an integer overflow.
5. The heap allocation routine allocates a buffer smaller than the expected size based on the overflowed integer.
6. Attacker sends a CMS.INCRBY command targeting indices that fall outside the allocated heap memory.
7. The out-of-bounds write corrupts heap metadata or surrounding data structures to control execution flow.
8. Attacker achieves remote code execution within the context of the Redis process.

## Impact

Successful exploitation allows a remote, authenticated attacker to achieve arbitrary code execution on the server hosting the Redis instance. This impact covers critical confidentiality, integrity, and availability (CVSS 8.8-9.8). The vulnerability affects deployments of Redis Stack and RedisBloom, potentially exposing infrastructure components relying on Redis for caching or data processing.

## Recommendation

1. Patch all Redis and RedisBloom instances to the secure versions listed in the vendor advisory: Redis < 6.2.17, 7.2.7, and 7.4.2.
2. Audit Redis access controls to ensure that only authorized clients possess the credentials required to interact with the service.
3. Implement network-level segmentation to restrict access to the Redis port (default 6379) to known, trusted application servers only.
4. Review Redis logs for abnormally large integer values used as arguments in CMS.INITBYDIM or related CMS commands, as these may indicate exploitation attempts.
