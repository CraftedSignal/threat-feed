---
title: Netty HTTP/3 Codec Vulnerability Leads to Denial of Service via Memory Exhaustion
slug: 2026-07-netty-http3-dos
description: A vulnerability in Netty's HTTP/3 `Http3FrameCodec`, tracked as CVE-2026-56816, allows an unauthenticated remote attacker to cause a denial of service by sending crafted reserved HTTP/3 frames with an excessively large, unvalidated payload length, leading to server memory exhaustion.
date: "2026-07-22T21:43:29Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - java
  - netty
  - http3
vendors:
  - Netty
products:
  - netty-codec-http3 (< 4.2.16.Final)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Deny Access to Resource
    evidence: A bad actor can send a reserved frame with a payload length of up to Integer.MAX_VALUE, causing the server to buffer the data in memory. This leads to an OOM and a gradual Denial of Service due to memory exhaustion as multiple streams are opened.
    confidence_band: high
cves:
  - id: CVE-2026-56816
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-hpcc-26xq-25fv
---

A high-severity denial-of-service vulnerability (CVE-2026-56816) has been identified in Netty's `netty-codec-http3` library, specifically affecting versions prior to `4.2.16.Final`. This flaw originates from the `Http3FrameCodec` implicitly trusting the `payLoadLength` field in reserved HTTP/3 frames without validation. An attacker can exploit this by sending a reserved frame with a `payLoadLength` value up to `Integer.MAX_VALUE`. Despite sending only a small amount of actual data, the affected server attempts to buffer memory up to the declared payload length. By opening multiple QUIC streams and repeating this action, a malicious actor can gradually exhaust the server's memory, leading to an Out-of-Memory (OOM) error and a complete denial of service for any application utilizing the vulnerable Netty HTTP/3 codec. This vulnerability poses a significant risk to the availability of services dependent on these Netty versions.

## Attack Chain

1. An unauthenticated remote attacker establishes a QUIC connection to a server running an affected version of Netty's HTTP/3 codec.
2. The attacker initiates multiple QUIC streams on the established connection.
3. On each stream, the attacker crafts and sends a reserved HTTP/3 frame (e.g., frame type `0x40 0x40`).
4. Within the reserved frame's header, the attacker specifies an extremely large `payLoadLength`, up to `Integer.MAX_VALUE`, which is read directly from the wire.
5. The Netty `Http3FrameCodec` (specifically `io.netty.handler.codec.http3.Http3FrameCodec#decodeFrame`) implicitly trusts and attempts to process this `payLoadLength` without any validation or upper bound enforcement for reserved frames.
6. The attacker then sends only a minimal amount of actual data, significantly less than the declared `payLoadLength`.
7. The server's `Http3FrameCodec` attempts to buffer incoming data up to the declared `payLoadLength`, leading to the allocation of a vast amount of memory for each active stream.
8. As the attacker repeats this process across multiple QUIC streams, the server's memory is gradually exhausted, resulting in an Out-of-Memory (OOM) exception and a denial of service for the application.

## Impact

The primary impact of successfully exploiting CVE-2026-56816 is a denial of service (DoS) due to gradual memory exhaustion. Any application or service that integrates Netty's `netty-codec-http3` library, specifically versions prior to `4.2.16.Final`, is susceptible. An attacker can render the affected service unresponsive and unavailable by repeatedly sending specially crafted HTTP/3 reserved frames. This can lead to significant operational disruptions, loss of revenue for businesses, and reputational damage due to service outages.

## Recommendation

* **Patch CVE-2026-56816 immediately**: Upgrade all instances of `netty-codec-http3` to version `4.2.16.Final` or newer to remediate CVE-2026-56816.
* **Monitor server resource utilization**: Implement monitoring for server memory and CPU utilization on systems running Netty HTTP/3 services to detect abnormal spikes indicative of DoS attempts.
