---
title: '@libp2p/kad-dht Unvalidated PUT_VALUE Records Allow Unbounded Disk Exhaustion'
slug: 2026-05-kad-dht-dos
description: An unauthenticated remote peer can exhaust the disk storage of any `@libp2p/kad-dht` node running in server mode by sending an unbounded stream of `PUT_VALUE` messages with crafted keys to bypass validation and cause disk exhaustion.
date: "2026-05-19T20:09:11Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - libp2p
  - kad-dht
  - denial-of-service
  - disk-exhaustion
vendors:
  - libp2p
products:
  - '@libp2p/kad-dht'
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-32mq-hpph-xfvr
rules:
  - title: Detect Libp2p Kad-DHT Unvalidated PUT_VALUE Attack
    description: Detects an unusual amount of PUT_VALUE messages with crafted keys (fewer than three slash-delimited parts) sent to a libp2p kad-dht node, indicating a potential denial-of-service attack.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - application
      - libp2p
  - title: Detect Libp2p Kad-DHT High PUT_VALUE Message Rate
    description: Detects a high rate of PUT_VALUE messages from a single peer to a libp2p kad-dht node, potentially indicating a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - application
      - libp2p
rules_count: 2
---

The `@libp2p/kad-dht` library is vulnerable to a denial-of-service attack where an unauthenticated remote peer can exhaust the disk storage of a node running in server mode. This is achieved by sending an unbounded stream of `PUT_VALUE` messages with specially crafted keys that bypass content validation. The vulnerability stems from two key defects in the code. First, the `verifyRecord` function silently returns success for keys with fewer than three slash-delimited parts, leading to unconditional writes to the datastore. Second, the RPC message loop lacks proper rate limiting or message count limits, allowing an attacker to stream an unlimited number of messages indefinitely by resetting the inactivity timeout with each message. This can lead to the victim node's datastore filling up until the host disk is exhausted, making the node unavailable. The issue affects `@libp2p/kad-dht` versions prior to the fix.

## Attack Chain

1. Attacker establishes a TLS handshake with the target `@libp2p/kad-dht` node without authentication.
2. Attacker opens a new stream to send `PUT_VALUE` messages. The target node can accept up to 32 concurrent inbound streams.
3. Attacker crafts a `PUT_VALUE` message with a key that has fewer than three slash-delimited parts (e.g., `\x01\x02\x03`).
4. The `verifyRecord` function in `packages/kad-dht/src/record/validators.ts` silently returns without validation because the key does not conform to the expected format.
5. The crafted record is written to the target node's datastore. Each message can contain up to 4MB of data due to the `DEFAULT_MAX_DATA_LENGTH`.
6. The target node resets the inactivity timeout (`this.incomingMessageTimeout`) after processing each message in the RPC loop in `packages/kad-dht/src/rpc/index.ts`.
7. The attacker repeats steps 3-6 indefinitely, sending a continuous stream of invalid `PUT_VALUE` messages within the 10-second timeout window.
8. The target node's datastore fills up with unvalidated data, exhausting the disk space and causing a denial-of-service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition. An attacker can remotely exhaust the disk space of any `@libp2p/kad-dht` node running in server mode, rendering it unavailable. Since the attack is unauthenticated and can be performed over multiple concurrent streams, it has the potential to impact a large number of nodes. The number of victims and the sectors targeted would depend on the deployment size of `@libp2p/kad-dht` nodes. If successful, legitimate services relying on the DHT network may be disrupted.

## Recommendation

*   Apply the patch or upgrade to a version of `@libp2p/kad-dht` that includes the fix for the unbounded `PUT_VALUE` vulnerability as detailed in [GHSA-32mq-hpph-xfvr](https://github.com/advisories/GHSA-32mq-hpph-xfvr).
*   Implement rate limiting or message count limits on incoming streams to prevent unbounded message loops in `packages/kad-dht/src/rpc/index.ts`.
*   Deploy the Sigma rule `Detect Libp2p Kad-DHT Unvalidated PUT_VALUE Attack` to detect unusual amounts of PUT_VALUE messages with crafted keys.
