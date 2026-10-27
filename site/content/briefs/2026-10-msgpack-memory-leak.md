---
brief_id: brief-2026-10-27-msgpack-memory-leak
event_id: brief-2026-10-27-msgpack-memory-leak
revision: 1
activity_at: "2026-10-27T17:57:55Z"
title: 'msgpack-python: Memory leak and use-after-free vulnerability (CVE-2026-114613)'
slug: 2026-10-msgpack-memory-leak
description: The msgpack-python C extension contains a memory leak and a reference count corruption vulnerability triggered during deserialization of malformed data, enabling denial of service and potential memory safety issues.
date: "2026-10-27T17:57:55Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source-confirmed vulnerability details; validation of patch environment required.
cpes:
  - cpe:2.3:a:msgpack:msgpack:*:*:*:*:*:python:*:*
products:
  - msgpack-python (< 1.2.3)
cves:
  - id: CVE-2026-114613
    cvss: 7.5
    epss: 0.0044
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-j586-36cw-2gc2
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade msgpack-python dependency to 1.2.3 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-114613
  hunt_leads:
    - lead: Monitor application process memory usage for rapid or anomalous growth during periods of high ingestion of MessagePack-serialized data
      data_needed:
        - Application process memory metrics (Resident Set Size)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Repeated malformed inputs can cause unbounded process memory growth and denial of service.
  mitigation_plan:
    - priority: immediate
      action: Upgrade msgpack-python to 1.2.3
      owner: IT Operations
      addresses: CVE-2026-114613
      evidence: GHSA-j586-36cw-2gc2
  gaps:
    - Lack of application-level logs indicating specific MessagePack deserialization failure patterns for the vulnerable endpoints.
---

The msgpack-python C extension (`msgpack._cmsgpack`) is vulnerable to an unbounded memory leak when deserializing MessagePack data that fails `strict_map_key` validation. The vulnerability occurs because the C extension fails to release references to constructed map values when a key is rejected. This can be exploited to cause a denial of service via memory exhaustion. 

Additionally, an audit identified a use-after-free condition in the streaming `Unpacker` API. Stale references to objects in the parser stack can lead to incorrect reference count decrements (double `Py_DECREF`) if parsing fails after a nested container is processed. This can result in application crashes or memory corruption. Both vulnerabilities are tracked under CVE-2026-114613.

## Impact

- **Memory Leak:** Observed retention of approximately 4 MiB of memory per failed parse, leading to rapid process memory growth and potential service instability.
- **Memory Safety:** The reference count corruption in the streaming API may lead to unpredictable application behavior, crashes, or use-after-free vulnerabilities.

## Recommendation

- Upgrade `msgpack` to version 1.2.3 or later immediately to address the memory leak and reference count corruption.
- If immediate patching is not possible, evaluate the use of the pure-Python implementation of `msgpack`, which is reported not to exhibit this specific leak, though it may have performance implications.
- Implement strict request-size and request-rate limiting at the application or WAF level for endpoints that accept MessagePack data to mitigate the impact of malicious inputs on memory utilization.
