---
title: Netty Bzip2Decoder Infinite Loop Vulnerability Leads to Event-Loop Thread Hang (CVE-2026-59901)
slug: 2026-07-netty-bzip2decoder-infinite-loop
description: A denial-of-service vulnerability exists in the `Bzip2Decoder` handler within Netty's `netty-codec-compression` and `netty-codec` libraries, allowing a remote attacker to exploit CVE-2026-59901 by providing a specially crafted bzip2 stream, which causes an infinite loop in the run-length encoding state machine, leading to the permanent hang of an event-loop thread and application denial of service.
date: "2026-07-22T21:52:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - netty
vendors:
  - Netty
products:
  - netty-codec-compression (>= 4.2.0.Final, < 4.2.16.Final)
  - netty-codec (< 4.1.136.Final)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Denial of Service
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: a denial-of-service attack through a malformed bzip2 stream that permanently captures the event-loop thread in an infinite loop
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-558v-64gr-wgg4
---

A high-severity denial-of-service (DoS) vulnerability, tracked as CVE-2026-59901, has been discovered in the `Bzip2Decoder` handler of the Netty networking framework. Specifically, the vulnerability affects the `netty-codec-compression` library (versions >= 4.2.0.Final, < 4.2.16.Final) and the `netty-codec` library (versions < 4.1.136.Final). This flaw allows a remote attacker to trigger an infinite loop within the run-length encoding (RLE) state machine of the `Bzip2BlockDecompressor.read()` method by supplying a malformed bzip2 compressed stream. When exploited, the infinite loop permanently consumes the application's event-loop thread, rendering the affected Netty-based application unresponsive and causing a denial of service. This vulnerability impacts any application using the affected Netty versions for bzip2 decompression, making prompt patching critical to maintain service availability.

## Attack Chain

1. An attacker identifies a target application utilizing vulnerable Netty versions (e.g., `netty-codec-compression` >= 4.2.0.Final, < 4.2.16.Final or `netty-codec` < 4.1.136.Final).
2. The attacker determines that the target application processes bzip2 compressed data inputs.
3. The attacker crafts a specially malformed bzip2 stream designed to specifically trigger an edge case in the run-length encoding (RLE) state machine.
4. The crafted malformed bzip2 stream is transmitted to the vulnerable application through its expected input mechanism (e.g., as part of an HTTP request payload, a file upload, or a message in a queue).
5. The Netty application receives the input and attempts to process the bzip2 compressed data using its `Bzip2Decoder` handler.
6. During the decompression process, the `Bzip2Decoder` handler invokes the `Bzip2BlockDecompressor.read()` method to handle the incoming stream.
7. The malformed bzip2 data causes the RLE state machine within `Bzip2BlockDecompressor.read()` to enter an infinite loop.
8. The event-loop thread responsible for processing the input becomes permanently tied up in this loop, causing the application to hang indefinitely and cease responding to further requests, achieving a denial of service.

## Impact

Successful exploitation of CVE-2026-59901 leads to a complete denial of service for any application using the vulnerable Netty components. This means the affected application will become unresponsive, unable to process new requests or maintain existing connections, effectively bringing down the service. While specific victim counts are not available, given Netty's widespread use in Java-based applications, a significant number of services could be at risk if not patched. The primary consequence is service unavailability, which can lead to significant operational disruptions, financial losses, and reputational damage depending on the critical nature of the affected service.

## Recommendation

* Patch CVE-2026-59901 immediately by upgrading `netty-codec-compression` to version `4.2.16.Final` or newer.
* Patch CVE-2026-59901 immediately by upgrading `netty-codec` to version `4.1.136.Final` or newer.
* Review applications for the presence of affected Netty versions listed in the "Affected Products" section that handle bzip2 compressed data.
