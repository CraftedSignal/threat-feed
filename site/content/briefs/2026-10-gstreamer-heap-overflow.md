---
brief_id: brief-2026-10-23-gstreamer-heap-overflow
event_id: brief-2026-10-23-gstreamer-heap-overflow
revision: 1
activity_at: "2026-10-23T06:43:25Z"
title: GStreamer libgstvideo heap buffer overflow (CVE-2026-86476)
slug: 2026-10-gstreamer-heap-overflow
description: A heap buffer overflow in GStreamer's libgstvideo via untrusted unixfd deserialization allows remote attackers to trigger out-of-bounds memory access, potentially leading to code execution.
date: "2026-10-23T06:43:25Z"
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
  validation_status: Verified against technical advisory details
cpes:
  - cpe:2.3:a:gstreamer:libgstvideo:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - heap-overflow
  - memory-corruption
vendors:
  - GStreamer
products:
  - libgstvideo (GStreamer 1.28.4 and earlier)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: With the heap write, the proof of concept overwrites the free function pointer in the header of a neighbouring GstMiniObject, places the command string where it lands in the first argument register, and triggers an unref so the forged pointer is called as system().
    confidence_band: high
cves:
  - id: CVE-2026-86476
    cvss: 8.4
    epss: 0.00209
    kev_status: "false"
references:
  - https://vulners.com/cve/CVE-2026-86476
  - https://github.com/0xSemizzz/CVE-2026-86476
  - https://sploitus.com/exploit?id=3FCE35B0-34B6-54F9-9C41-15CC8CFC9FD5&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory systems utilizing GStreamer unixfdsrc for inter-process communication
      owner: Security Engineering
      due: 48h
      evidence: Technical report highlights vulnerability in pipelines utilizing unixfd transport
  mitigation_plan:
    - priority: immediate
      action: Upgrade or patch GStreamer to a version that implements bounds checking in default_map and video_meta_deserialize
      owner: IT Operations
      addresses: CVE-2026-86476
      evidence: Source provides explicit fix directions
---

A heap buffer overflow vulnerability exists in the GStreamer `libgstvideo` component (specifically within `gst-plugins-base`), identified as CVE-2026-86476. The vulnerability stems from insufficient validation of `GstVideoMeta` structures when deserialized from untrusted `unixfd` peers. Attackers can provide fabricated plane strides within the metadata, leading to out-of-bounds reads and writes during frame processing. Proof-of-concept code demonstrates that these primitives can be used for information disclosure or heap-based remote code execution by overwriting function pointers.

## Attack Chain
1. An attacker establishes a connection with a target process over a `unixfd` transport.
2. The attacker sends a serialized `GstVideoMeta` structure containing intentionally oversized or negative plane strides.
3. The target receiver deserializes the malicious meta-data without performing range checks against the backing buffer size.
4. The target process maps the frame, with `default_map()` failing to validate the geometry against the actual memory allocation.
5. During subsequent processing (e.g., in `videoconvert`), the system performs `memcpy` or ORC kernel operations based on the attacker-controlled strides.
6. Memory operations occur outside the buffer boundaries, resulting in either a crash (read) or corruption of adjacent heap objects (write).
7. The attacker leverages the write primitive to overwrite function pointers in a neighbouring `GstMiniObject`.
8. The application is triggered to call the corrupted pointer, redirecting control flow to attacker-supplied logic (e.g., `system()`).

## Impact
Confirmed impact includes out-of-bounds information disclosure and heap-based memory corruption. Demonstrations indicate potential for arbitrary code execution in pipelines that accept video buffers over `unixfd` from untrusted sources, particularly sandboxed decoders or portal-style privilege-boundary pipelines.

## Recommendation
- Inventory systems utilizing GStreamer `unixfdsrc` elements, specifically those handling media frames across process or privilege boundaries.
- Apply security patches to GStreamer and dependent projects as soon as vendors release updates addressing the three validation points identified in the advisory: plane extent checks in `default_map()`, validation in the meta branch of `gst_video_frame_map_id()`, and range checks in `video_meta_deserialize()`.
- Isolate media processing pipelines that consume data from untrusted sources to minimize the impact of potential memory corruption.
