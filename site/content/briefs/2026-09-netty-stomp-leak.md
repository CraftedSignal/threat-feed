---
title: Denial of Service via ByteBuf Memory Leak in Netty STOMP Codec
slug: 2026-09-netty-stomp-leak
description: An unauthenticated remote attacker can cause cumulative memory exhaustion and service denial by sending incomplete STOMP frames that trigger a buffer leak in Netty's StompSubframeDecoder.
date: "2026-09-26T19:00:15Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:netty:netty:*:*:*:*:*:*:*:*
products:
  - netty-codec-stomp (<= 4.1.137.Final, 4.2.0.Final - 4.2.17.Final)
cves:
  - id: CVE-2026-100657
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100657
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all applications using netty-codec-stomp and prepare for update to 4.1.138.Final or 4.2.18.Final
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-100657 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade netty-codec-stomp to version 4.1.138.Final or 4.2.18.Final
      owner: IT Operations
      addresses: CVE-2026-100657
      evidence: NVD vulnerability details
---

A memory leak vulnerability, identified as CVE-2026-100657, exists within the `io.netty:netty-codec-stomp` component of the Netty framework. The vulnerability resides in the `StompSubframeDecoder` class, which improperly manages `ByteBuf` allocations when processing frames. Specifically, upon reading a frame's content-length, the decoder allocates a chunk buffer and stores it in an instance field while awaiting a mandatory terminating NUL byte. 

If the terminating NUL byte is never received, the decoder fails to release the allocated buffer. This occurs because the `skipNullCharacter` method throws a `Signal` that extends `Error` rather than `Exception`, bypassing the existing `catch(Exception)` cleanup logic. Furthermore, the decoder lacks overrides for `handlerRemoved0` or `channelInactive`, ensuring the memory persists even after the connection is closed. By repeatedly sending incomplete frames, an attacker can leak memory from the pooled allocator, leading to process memory exhaustion and denial-of-service. The issue affects Netty versions up to 4.1.137.Final and 4.2.0.Final through 4.2.17.Final.

## Impact

Successful exploitation results in a persistent denial-of-service condition due to application-level memory exhaustion. Because the memory is pooled and not returned to the allocator or reclaimed by garbage collection, the impact is cumulative over the lifetime of the process, effectively terminating services that rely on the affected STOMP codec.

## Recommendation

Prioritize the identification and patching of systems utilizing the affected Netty codec versions.

* Upgrade all instances of `netty-codec-stomp` to version 4.1.138.Final or 4.2.18.Final to resolve the `ByteBuf` management logic.
* Audit application dependencies to identify vulnerable library versions listed in CVE-2026-100657.
* Monitor application memory usage patterns and `OutOfMemoryError` events, as sustained spikes in heap consumption may indicate active exploitation of this memory leak.
