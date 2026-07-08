---
title: 'CVE-2026-59803: rpcx Denial-of-Service Vulnerability'
slug: 2026-07-rpcx-dos
description: A denial-of-service vulnerability (CVE-2026-59803) in rpcx through version 1.9.3 allows an unauthenticated attacker to trigger out-of-memory conditions and service unavailability by sending a small, compressed message that expands to gigabytes of memory during decompression.
date: "2026-07-08T20:18:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - rpcx
  - go-lang
products:
  - rpcx <= 1.9.3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Resource Development
    technique_id: T1499
    technique_name: Resource Exhaustion
    evidence: a single unauthenticated connection can send a small (under 2 MB) gzip-compressed message that expands to gigabytes of heap allocation, leading to out-of-memory conditions and service unavailability.
    confidence_band: high
cves:
  - id: CVE-2026-59803
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59803
---

A critical denial-of-service (DoS) vulnerability, tracked as CVE-2026-59803, exists in the popular rpcx Go RPC framework, affecting all versions up to 1.9.3. This vulnerability stems from improper handling of compressed messages within the `protocol.Message.Decode` function in `protocol/message.go`. An unauthenticated attacker can exploit this by sending a specially crafted, small (under 2 MB) gzip-compressed message. The `util.Unzip` function, used for decompression, lacks size limits on its output, allowing the small input to expand into gigabytes of memory allocation. The existing `protocol.MaxMessageLength` guard is ineffective as it only checks the compressed frame length, not the expanded decompressed size. This "decompression bomb" leads to out-of-memory conditions, causing the rpcx service to crash and become unavailable.

## Attack Chain

1. An unauthenticated attacker establishes a connection to a vulnerable rpcx service.
2. The attacker crafts a malicious rpcx message with the compression flag set.
3. The payload of this message consists of a small (under 2 MB) gzip-compressed data stream engineered to expand exponentially upon decompression.
4. The attacker sends this crafted message over the established connection to the rpcx service.
5. The rpcx service's `readRequest` function receives the message prior to any authentication checks.
6. The `protocol.Message.Decode` function is invoked to process the message, which subsequently calls `util.Unzip` to decompress the payload.
7. During the decompression process, the maliciously crafted payload expands to consume gigabytes of the service's memory.
8. The service encounters an out-of-memory (OOM) condition, leading to its crash and resulting in a denial of service.

## Impact

The primary impact of CVE-2026-59803 is the complete denial of service for affected rpcx applications. Exploitation is unauthenticated, meaning any external attacker can crash vulnerable services, rendering them unavailable to legitimate users. This can lead to significant operational disruption, data unavailability, and potential financial losses for organizations relying on rpcx for their services. While no specific victim count or targeted sectors are available, any organization deploying rpcx services through version 1.9.3 is at risk of this easily triggered DoS.

## Recommendation

* Patch CVE-2026-59803 immediately by upgrading rpcx to a patched version (1.9.4 or later) or applying commit 047aec1.
* Monitor your rpcx application hosts for sudden spikes in memory usage or unexpected service restarts, which could indicate attempted exploitation of CVE-2026-59803.
