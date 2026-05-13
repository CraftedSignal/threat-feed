---
title: Klever-Go MultiDataInterceptor Remote OOM via Compressed Payload
slug: 2026-05-klever-go-oom
description: Klever-Go's MultiDataInterceptor is vulnerable to a remote denial-of-service (DoS) attack. By sending a crafted compressed P2P payload, an unauthenticated attacker can trigger excessive memory allocation on the receiving node, leading to an out-of-memory (OOM) condition and potentially disrupting chain liveness.
date: "2026-05-13T01:37:17Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - denial-of-service
  - decompression-bomb
  - klever-go
vendors:
  - klever-io
products:
  - klever-go
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-87m7-qffr-542v
rules:
  - title: Detect Klever-Go Excessive GZIP Decompression Attempt
    description: Detects potential attempts to exploit the Klever-Go GZIP decompression vulnerability by monitoring for process creation that might indicate a system crash related to excessive memory allocation, for example by looking for log messages indicating an OOM condition.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Klever-Go Decompression Bomb Network Traffic
    description: Detects potentially malicious network traffic to Klever-Go nodes with abnormally high compression ratios, indicative of a decompression bomb attack
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Klever-Go's `MultiDataInterceptor` is vulnerable to a denial-of-service attack stemming from uncontrolled decompression within the `Batch.Decompress` function. This flaw allows any peer on a topic served by `MultiDataInterceptor` to trigger multi-gigabyte heap allocations on the receiving node through a sub-50 KiB gossip payload. A single malicious packet can OOM-kill a validator with standard memory provisioning, potentially halting chain liveness. Discovered during an internal security review, the vulnerability affects `core/process/interceptors/multiDataInterceptor.go` at commit `405d01b0abbf0d3e73b4a990bd7394a01f200dc2`. It's distinct from the `GHSA-74m6-4hjp-7226` throttler-slot-leak issue but resides in adjacent code within the same call path. The attack leverages the lack of size validation during decompression, enabling attackers to send small, compressed payloads that expand into enormous data structures in memory.

## Attack Chain

1. Attacker crafts a malicious compressed payload. This payload is designed to decompress into an extremely large data structure, such as a `Batch` containing millions of entries.
2. The malicious payload is sent to a Klever-Go node participating in a topic served by `MultiDataInterceptor`.
3. The `MultiDataInterceptor.ProcessReceivedMessage` function receives the gossip message.
4. Within `ProcessReceivedMessage`, the `b.Decompress` function is called on the received batch data, as the `IsCompressed` flag is set.
5. `Batch.Decompress` calls `decompressGzip` which uses `io.ReadAll` without any size limits, leading to an unbounded memory allocation based on the compressed data.
6. After successful decompression, `Decompress` attempts to unmarshal the inflated bytes back into a `Batch` structure, again without any size constraints.
7. The attacker-controlled `DataSize` field is not validated, allowing a small compressed packet to expand into a huge memory allocation.
8. The memory allocation leads to an out-of-memory (OOM) condition, crashing the Klever-Go node and disrupting chain liveness.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition on Klever-Go nodes. A single, crafted packet is sufficient to exhaust the memory resources of a validator, leading to its crash. This can impact chain liveness and availability, potentially affecting the entire network if multiple validators are targeted. The low payload size coupled with high amplification makes it easy for attackers to disrupt Klever-Go networks.

## Recommendation

*   Apply the patch that remediates the vulnerability in `data/batch/batch.go` and `core/process/interceptors/multiDataInterceptor.go` as outlined in [GHSA-87m7-qffr-542v](https://github.com/advisories/GHSA-87m7-qffr-542v).
*   Monitor network traffic for abnormally large compressed payloads being sent to Klever-Go nodes using the rules provided below.
*   Implement rate limiting and size validation on incoming gossip messages to mitigate the impact of similar decompression-based attacks.
