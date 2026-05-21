---
title: js-libp2p Gossipsub Memory Exhaustion via Subscription Flood
slug: 2026-05-js-libp2p-dos
description: A memory exhaustion vulnerability exists in `@libp2p/gossipsub` due to unbounded subscription handling, allowing a single attacker to exhaust a Node.js heap by flooding unique topic subscriptions, leading to denial-of-service.
date: "2026-05-21T21:40:43Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - dos
  - memory-exhaustion
  - libp2p
vendors:
  - libp2p
products:
  - js-libp2p
  - '@libp2p/gossipsub'
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
  - https://github.com/advisories/GHSA-4f8r-922h-2vgv
rules:
  - title: Detect High Topic Count in Gossipsub Subscriptions
    description: Detects a large number of unique topic subscriptions within a short timeframe, indicative of a potential memory exhaustion attack in Gossipsub.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - application
      - gossipsub
rules_count: 1
---

A memory exhaustion vulnerability has been identified in `@libp2p/gossipsub`, a component of the js-libp2p library. The vulnerability stems from three design flaws: the lack of a decode-level cap on subscription entries per RPC (`defaultDecodeRpcLimits.maxSubscriptions = Infinity`), unbounded growth in the `handleReceivedSubscription` function, and the failure to remove empty Sets from `this.topics` after a peer disconnect in the `removePeer` function. This allows an unauthenticated peer to exhaust the Node.js heap of a gossipsub node with default options by sending a flood of unique topic subscriptions. A single 4MB frame can carry 349,525 unique topic SUBSCRIBE entries, causing approximately 89MB of heap growth, leading to a crash after around 17 frames, demonstrating a significant amplification factor. This affects any gossipsub node with default options.

## Attack Chain

1.  Attacker dials a victim node and opens a gossipsub stream.
2.  The attacker's initial score is 0, which is greater than the default `gossipThreshold` of -10, allowing subscriptions to be processed immediately without score checks.
3.  The attacker constructs a malicious RPC message containing 349,525 SUBSCRIBE entries, each with a unique 6-character topic string. The total encoded size of this RPC is approximately 4MB.
4.  The victim's `handleReceivedRpc` processes the RPC and iterates through each subscription entry, calling `handleReceivedSubscription` for each unique topic.
5.  `handleReceivedSubscription` adds each new topic to the `this.topics` map without any limits or per-peer count restrictions, leading to uncontrolled memory allocation.
6.  The victim's `this.topics` map grows by 349,525 entries, consuming approximately 89MB of heap space and blocking the event loop for approximately 224ms.
7.  The attacker reconnects and repeats the process, sending additional RPCs with unique topic subscriptions. No score decay or penalties are applied.
8.  After approximately 17 rounds, the Node.js process exhausts its 1.5GB heap limit, resulting in an Out-Of-Memory (OOM) crash, causing a denial-of-service.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition, as the target Node.js process crashes due to memory exhaustion. The attack requires only approximately 68MB of total attacker bandwidth, achievable in approximately 5 seconds at 100Mbps. The vulnerability affects any gossipsub node running with default options, making it a widespread risk. The memory leak in `removePeer` also contributes to long-term performance degradation as `this.topics` accumulates entries.

## Recommendation

*   Apply patches to `@libp2p/gossipsub` to limit the number of subscriptions accepted per RPC and implement per-peer topic count limits.
*   Implement a mechanism to remove empty Sets from `this.topics` in the `removePeer` function to prevent memory leaks, mitigating defect 3.
*   Deploy the Sigma rule "Detect High Topic Count in Gossipsub Subscriptions" to identify and potentially block malicious subscription floods.
*   Monitor Node.js process memory usage and restart gossipsub nodes exceeding a defined memory threshold to mitigate the impact of memory exhaustion.
*   Review and adjust the default `gossipThreshold` to require higher scores for subscription processing, potentially mitigating step 2 of the attack chain.
