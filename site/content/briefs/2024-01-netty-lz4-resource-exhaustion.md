---
title: Netty Lz4FrameDecoder Resource Exhaustion Vulnerability
slug: 2024-01-netty-lz4-resource-exhaustion
description: Netty's Lz4FrameDecoder is vulnerable to resource exhaustion, where an attacker can cause excessive memory allocation by sending a small, crafted header, leading to a denial-of-service condition; this affects netty-codec-compression versions up to 4.2.12.Final and netty-codec versions up to 4.1.132.Final.
date: "2026-05-07T00:20:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - resource-exhaustion
  - denial-of-service
  - netty
vendors:
  - Netty
products:
  - netty-codec-compression (<= 4.2.12.Final)
  - netty-codec (<= 4.1.132.Final)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Resource Hijacking
references:
  - https://github.com/advisories/GHSA-mj4r-2hfc-f8p6
rules:
  - title: Netty Lz4 Frame Decoder Large Allocation
    description: Detects LZ4 frames with excessively large declared decompressed length, indicating a potential resource exhaustion attack.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - windows
  - title: Netty Lz4 Decoder Exception
    description: Detects DecoderException errors related to Lz4FrameDecoder, potentially indicating a malicious frame.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1499.004
    data_sources:
      - application
      - linux
rules_count: 2
---

The Netty framework is susceptible to a resource exhaustion vulnerability in its Lz4FrameDecoder. This vulnerability stems from the decoder's reliance on header fields for buffer sizing. An attacker can exploit this by sending a minimal (22-byte) crafted header that specifies a large decompressed length (up to 32MB per block). This forces the server to allocate an unnecessarily large ByteBuf before the LZ4 decompression even occurs, consuming significant memory resources. The vulnerability affects netty-codec-compression versions up to 4.2.12.Final and netty-codec versions up to 4.1.132.Final. By repeatedly sending these malicious headers, an attacker can exhaust server memory, leading to a denial-of-service condition. This is especially critical in environments where Netty is used to handle network communications and where untrusted clients are allowed to connect.

## Attack Chain

1.  The attacker establishes a network connection to a Netty-based server using the affected Lz4FrameDecoder.
2.  The attacker crafts a malicious LZ4 frame header, setting the `decompressedLength` field to a large value (e.g., 32MB). The complete header can be as small as 22 bytes.
3.  The attacker sends the crafted header to the server.
4.  The Lz4FrameDecoder on the server receives the header and allocates a ByteBuf based on the attacker-controlled `decompressedLength` value.
5.  The decoder attempts to decompress the (nonexistent or minimal) compressed data, which may trigger an `IndexOutOfBoundsException` or other decompression error.
6.  The server's memory resources are consumed by the allocated ByteBuf, even if the decompression fails.
7.  The attacker repeats steps 3-6 to continuously allocate memory.
8.  The server's memory is exhausted, leading to a denial-of-service condition for legitimate users.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service (DoS) condition. An attacker can exhaust the server's memory resources by sending a series of small, malicious requests. The number of victims would depend on the deployment of the Netty framework and the exposure of vulnerable services to untrusted clients. The sectors most affected are those relying on Netty for network communication, such as messaging platforms, application servers, and data streaming services. If the attack succeeds, the affected service becomes unavailable, disrupting normal operations and potentially leading to data loss or service outages.

## Recommendation

*   Upgrade to a non-vulnerable version of `io.netty:netty-codec-compression` (greater than 4.2.12.Final) or `io.netty:netty-codec` (greater than 4.1.132.Final) to patch CVE-2026-42583.
*   Implement per-channel and aggregate limits on incoming data and memory allocation to mitigate the impact of resource exhaustion attacks.
*   Monitor network traffic for unusually small LZ4 frames with excessively large declared decompressed lengths. Deploy the `Netty Lz4 Frame Decoder Large Allocation` Sigma rule to your SIEM to detect this pattern.
