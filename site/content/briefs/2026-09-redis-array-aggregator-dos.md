---
title: Resource Exhaustion in RedisArrayAggregator
slug: 2026-09-redis-array-aggregator-dos
description: A vulnerability in RedisArrayAggregator allows remote attackers to trigger memory exhaustion via a crafted RESP payload that forces eager allocation of array capacity.
date: "2026-09-18T14:05:50Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:redis:redis_array_aggregator:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - memory-exhaustion
  - redis
vendors:
  - Redis
products:
  - RedisArrayAggregator
cves:
  - id: CVE-2026-93572
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93572
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  enrichment_needed:
    - item: CVE-2026-93572 fixed version
      owner: CTI
      reason: Necessary for remediation planning.
      evidence: Source does not provide fix details.
  mitigation_plan:
    - priority: medium_term
      action: Monitor application heap usage and memory pressure in components using RedisArrayAggregator.
      owner: IT Operations
      addresses: CVE-2026-93572
      evidence: Vulnerability allows heap-based memory exhaustion via crafted RESP payloads.
---

CVE-2026-93572 is a resource exhaustion vulnerability affecting the RedisArrayAggregator component. The issue stems from the eager allocation of ArrayList capacity based on nested RESP array headers. The implementation checks 'maxElements' and 'maxNestedArrayDepth' independently, failing to account for the cumulative memory impact of nested array allocations. An attacker can send a series of nested RESP array headers, each specifying a large length, which forces the application to create 'new ArrayList&lt;RedisMessage>(length)' for every header. Because the memory is reserved upon receipt of the header before the actual array elements are processed, an attacker can consume massive amounts of system memory with a relatively small input payload, leading to a Denial of Service (DoS) state. This vulnerability highlights the risk of relying on independent limit checks in recursive parsing logic.

## Impact

Successful exploitation results in a Denial of Service due to memory exhaustion. The vulnerability allows an attacker to disproportionately consume system memory relative to the size of the malicious input, which can crash the application or destabilize the host system depending on the available heap space and resource constraints.

## Recommendation

1. Audit applications utilizing RedisArrayAggregator to determine if user-controlled input can reach the affected RESP decoding logic.
2. Implement strict input validation or application-level rate limiting for incoming RESP traffic until a patch is available.
3. Monitor application memory usage and heap allocation patterns; unusual spikes correlated with high-frequency incoming array headers may indicate exploitation attempts.
