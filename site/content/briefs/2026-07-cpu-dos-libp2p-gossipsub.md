---
title: CPU DoS Vulnerability in libp2p gossipsub
slug: 2026-07-cpu-dos-libp2p-gossipsub
description: A critical vulnerability in the `@libp2p/gossipsub` library allows an unauthenticated attacker to cause a CPU-based Denial of Service by sending oversized IHAVE and IWANT control messages, which are synchronously processed, leading to Node.js event loop exhaustion and service disruption.
date: "2026-07-10T16:07:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - cpu-exhaustion
  - javascript
  - nodejs
  - library-vulnerability
vendors:
  - libp2p
products:
  - '@libp2p/gossipsub'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: gossipsub processes IHAVE and IWANT control messages by iterating every received message ID synchronously before doing anything with the results. ... Iterating that many IDs blocks the Node.js event loop for around 200ms per call.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-cwc9-cp4j-mcvv
---

Unauthenticated attackers can exploit a CPU-based Denial of Service vulnerability present in the `@libp2p/gossipsub` library when running with default configurations. This vulnerability, tracked under GHSA-cwc9-cp4j-mcvv, involves sending specially crafted, oversized IHAVE and IWANT control messages over the libp2p network. These messages contain large arrays of message IDs that the library processes synchronously without adequate size or rate limits, particularly for IWANT messages. This synchronous and uncapped processing can block the Node.js event loop for extended periods, consuming significant CPU resources and leading to service disruption. While the IHAVE variant may require multiple Sybil peers for sustained impact, the IWANT variant allows a single malicious peer to maintain high event loop utilization indefinitely, severely affecting the availability of applications relying on `@libp2p/gossipsub`.

## Attack Chain

1. An unauthenticated attacker establishes a connection to a victim Node.js application running `@libp2p/gossipsub`.
2. The attacker subscribes to a topic that the victim is also subscribed to, ensuring they are part of the same gossipsub mesh.
3. (For IHAVE variant) The attacker coordinates approximately 10 Sybil peers, each sending a single 4MB RPC frame containing a `ControlIHave` entry with around 180,000 random message IDs.
4. (For IWANT variant) A single attacker peer continuously streams 4MB RPC frames, each containing a `ControlIWant` entry with approximately 180,000 random, non-existent message IDs.
5. The victim's `@libp2p/gossipsub` instance synchronously processes the large arrays of message IDs for each received control message.
6. This extensive synchronous iteration blocks the Node.js event loop for significant durations (e.g., ~135ms per 4MB frame), leading to high CPU utilization.
7. For the IWANT variant, due to the complete lack of internal rate limiting, a single peer can sustain high event loop utilization (e.g., above 80%) indefinitely.
8. The prolonged event loop blockage culminates in a CPU-based Denial of Service, rendering the Node.js application unresponsive and disrupting its services.

## Impact

A successful exploitation of this vulnerability results in a CPU-based Denial of Service (DoS) for any Node.js application utilizing the `@libp2p/gossipsub` library with default settings. The core impact is the exhaustion of the application's CPU resources and the indefinite blocking of the Node.js event loop, leading to the application becoming unresponsive. This directly compromises the availability of the affected services, potentially impacting decentralized applications or systems reliant on libp2p for peer-to-peer communication. No specific victim counts or targeted sectors were mentioned, but the nature of the vulnerability means any deployed instance is at risk.

## Recommendation

* Update the `@libp2p/gossipsub` library to a patched version once available to address the underlying vulnerability.
* Configure `opts.decodeRpcLimits` to set explicit, non-infinite maximum values for `maxIhaveMessageIDs` and `maxIwantMessageIDs` to cap the number of message IDs processed per frame.
