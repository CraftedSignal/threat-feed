---
title: Netty HTTP/3 QPACK Literal Unbounded Allocation Vulnerability
slug: 2024-01-netty-http3-qpack
description: A vulnerability in Netty's HTTP/3 QPACK decoder allows an attacker to cause a denial of service by sending a crafted HTTP/3 header that triggers excessive memory allocation, leading to a server crash.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - netty
  - http3
  - qpack
  - denial-of-service
  - vulnerability
vendors:
  - Netty
products:
  - netty-codec-http3 (<= 4.2.12.Final)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-2c5c-chwr-9hqw
rules:
  - title: Detect Large Allocation in Netty HTTP/3 QPACK Decoding
    description: Detects potential exploitation of the Netty HTTP/3 QPACK vulnerability by monitoring for excessive memory allocation events associated with HTTP/3 header decoding.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1588
    data_sources:
      - process_creation
      - linux
  - title: Detect Potential HTTP/3 QPACK DoS Attempt (Network)
    description: This rule detects a potential Denial-of-Service (DoS) attack attempt exploiting the Netty HTTP/3 QPACK vulnerability by monitoring for HTTP/3 HEADERS frames with unusually large QPACK sections.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - firewall
  - title: Detect Potential HTTP/3 QPACK DoS Attempt (Webserver)
    description: Detects potentially malicious HTTP/3 requests based on abnormal header size.  This is a heuristic and may require tuning.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
rules_count: 3
---

A vulnerability exists in Netty's HTTP/3 QPACK decoder (versions 4.2.12.Final and earlier) that can be exploited to cause a denial-of-service (DoS) condition. The vulnerability stems from the `io.netty.handler.codec.http3.QpackDecoder#decodeHuffmanEncodedLiteral` function, which allocates memory for HTTP/3 headers based on lengths provided in the header itself, without properly validating that the declared length corresponds to available data. A malicious actor can craft a small HTTP/3 HEADERS frame containing a QPACK section that decodes to a large non-Huffman name length, causing the server to allocate a large byte array (on the order of a gigabyte). This can exhaust server memory, leading to performance degradation or a complete crash.

## Attack Chain

1. The attacker crafts an HTTP/3 HEADERS frame with a malicious QPACK section.
2. The QPACK section is designed to trigger the non-Huffman branch of `io.netty.handler.codec.http3.QpackDecoder#decodeHuffmanEncodedLiteral`.
3. The attacker sets a very large length value for a string literal within the QPACK section. The encoding allows a large length to be expressed in few bytes.
4. The Netty server receives the malicious HTTP/3 HEADERS frame.
5. The `QpackDecoder` attempts to allocate a byte array of the size specified in the malicious header using `new byte[length]`.
6. Due to the missing length validation, the server allocates a potentially gigabyte-sized byte array.
7. The server experiences high memory consumption and potential resource exhaustion.
8. The server slows down, stalls, or crashes due to the excessive memory allocation.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition, where the server becomes unresponsive or crashes. This affects applications using the vulnerable versions of `netty-codec-http3`. A single crafted HTTP/3 HEADERS frame can trigger gigabytes of memory allocation, making the server susceptible to resource exhaustion under relatively low request volumes. This can disrupt services, impacting availability and potentially leading to data loss or corruption.

## Recommendation

*   Upgrade to a patched version of `netty-codec-http3` that addresses the vulnerability.
*   Deploy the Sigma rule below to detect attempts to exploit this vulnerability by monitoring for unusually large memory allocations associated with HTTP/3 header decoding.
*   Implement rate limiting on HTTP/3 requests to mitigate the impact of a large number of malicious requests.
*   Monitor server resource utilization (CPU, memory) for unusual spikes that may indicate exploitation attempts.
