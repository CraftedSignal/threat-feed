---
title: Netty SPDY SETTINGS Frame Denial of Service Vulnerability
slug: 2026-07-netty-spdy-dos
description: A high-severity vulnerability, CVE-2026-55831, in Netty's SPDY SETTINGS decoder allows a remote unauthenticated attacker to trigger a denial of service by sending a crafted SPDY/3.1 SETTINGS frame that leads to excessive heap growth and CPU consumption due to unbounded map entries in `DefaultSpdySettingsFrame`.
date: "2026-07-22T21:08:13Z"
lastmod: "2026-07-22T21:34:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:netty:netty:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - netty
  - spdy
  - java
  - memory-leak
  - DoS
vendors:
  - Netty
products:
  - netty-codec-http (4.2.0.Final - 4.2.15.Final)
  - netty-codec-http (4.1.0.Final - 4.1.135.Final)
  - netty-codec-http (>= 4.2.0.Final, <= 4.2.15.Final)
  - netty-codec-http (>= 4.1.0.Final, <= 4.1.135.Final)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
    evidence: The source mentions a proof-of-concept (PoC) for the vulnerability, which is a tool used to demonstrate and potentially exploit the flaw.
    confidence_band: med
  - tactic_id: TA0042
    tactic_name: Resource Exhaustion
    technique_id: T1499
    technique_name: Application-Layer Denial of Service
    evidence: A remote unauthenticated network peer that can speak SPDY/3.1 to a Netty pipeline containing `SpdyFrameCodec` can trigger resource-exhaustion denial of service.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: The user-visible effect is denial of service through compression-amplified CPU and allocation churn.
    confidence_band: high
cves:
  - id: CVE-2026-55831
    cvss: 7.5
    epss: 0.0063
references:
  - https://github.com/advisories/GHSA-6jqx-86gh-f27w
  - https://github.com/advisories/GHSA-mvh2-crg5-v77c
  - https://github.com/advisories/GHSA-jppx-w49h-x2qq
iocs:
  - type: url
    value: https://github.com/user-attachments/files/28445737/poc.zip
ioc_counts:
  url: 1
updates:
  - at: "2026-07-22T21:25:39Z"
    level: L1
    summary: 'merged source coverage: Netty SPDY Zlib Header Decoding Denial of Service Vulnerability'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-mvh2-crg5-v77c
  - at: "2026-07-22T21:34:03Z"
    level: L1
    summary: 'merged source coverage: Netty SpdyHttpDecoder ByteBuf Reference Leak Leads to Native Memory Exhaustion'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-jppx-w49h-x2qq
---

A remote unauthenticated denial of service vulnerability, identified as CVE-2026-55831, affects Netty's `netty-codec-http` library, specifically versions 4.2.0.Final through 4.2.15.Final and 4.1.0.Final through 4.1.135.Final. The flaw lies within the SPDY SETTINGS decoder, which does not impose an implementation-level cap on the number of unique setting IDs it will accept and materialize in its `DefaultSpdySettingsFrame`'s internal `TreeMap`. Attackers can exploit this by sending a specially crafted SPDY/3.1 SETTINGS frame containing up to 262,144 unique setting IDs. This leads to significant heap memory exhaustion, estimated at 17-18 MiB per frame, and high CPU utilization due to ordered-map insertion work, effectively rendering the affected Netty application unresponsive. The vulnerability highlights a critical resource management oversight in handling protocol-level data that can be manipulated by external parties.

## Attack Chain

1. A remote, unauthenticated attacker establishes a network connection to a server running an affected Netty application that utilizes `SpdyFrameCodec`.
2. The attacker crafts a malicious SPDY/3.1 SETTINGS frame, ensuring it is syntactically valid according to the SPDY specification.
3. The crafted frame includes a large number of unique 24-bit setting IDs, up to the maximum allowed by the 24-bit frame-length limit, such as 262,144 entries.
4. The `SpdyFrameCodec.decode()` method receives the inbound SPDY bytes, including the malicious SETTINGS frame.
5. The decoder reads the peer-controlled flags and 24-bit frame length, accepting the SETTINGS frame as valid if `length >= 4` and the payload is divisible into 8-byte entries matching the `numSettings` count.
6. For each unique setting ID and value pair supplied by the attacker, the `DefaultSpdySettingsFrame.setValue()` method is called, which inserts a new `Setting` into its internal `TreeMap`.
7. Due to the absence of a count budget or size limit during `TreeMap` insertion, the `DefaultSpdySettingsFrame` materializes all 262,144 attacker-controlled entries.
8. This process consumes approximately 17-18 MiB of heap memory and significant CPU cycles for ordered-map insertions per frame, leading to a resource-exhaustion denial of service for the Netty application.

## Impact

Successful exploitation of CVE-2026-55831 by a remote unauthenticated network peer results in a denial of service condition for applications utilizing affected Netty versions (v4.2.0.Final-4.2.15.Final and v4.1.0.Final-4.1.135.Final) with `SpdyFrameCodec`. The attack causes substantial heap memory growth (approx. 17-18 MiB per decoded frame) and high CPU utilization due to the unbounded insertion of attacker-controlled entries into a `TreeMap`. This resource exhaustion will render the application unresponsive, preventing it from serving legitimate users and potentially requiring manual intervention to restore service. The attack does not require authentication and can be executed over the network, making it a severe threat to the availability of affected services.

## Recommendation

* Patch CVE-2026-55831 immediately by updating `maven/io.netty:netty-codec-http` to a patched version (e.g., above 4.2.15.Final or 4.1.135.Final) to prevent resource-exhaustion denial of service.
* Monitor application logs for sudden, unexplained increases in memory consumption or CPU utilization in Netty applications, which could indicate attempts to exploit CVE-2026-55831.
* Implement network intrusion detection systems (NIDS) to monitor for unusually large or malformed SPDY/3.1 SETTINGS frames that match the characteristics described in the attack chain.
