---
title: Zebra Block Discovery Denial-of-Service via Gossip Queue Saturation and Syncer Poisoning
slug: 2024-01-zebra-block-discovery-dos
description: A denial-of-service vulnerability exists in Zebra's block discovery pipeline, allowing an unauthenticated remote attacker to permanently halt all new block discovery on a targeted node by exploiting weaknesses in the gossip, syncer, and download subsystems.
date: "2024-01-02T10:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - denial-of-service
  - zebra
  - block-discovery
  - gossip
  - syncer
vendors:
  - Zebra
products:
  - zebrad (< 4.4.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-44499
references:
  - https://github.com/advisories/GHSA-h9hm-m2xj-4rq9
rules:
  - title: Detect Zebra Syncer Path Degradation
    description: Detects connections sending empty responses to FindBlocks or FindHeaders messages, indicating syncer path degradation attempts.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - linux
  - title: Detect Excessive inv Message Traffic
    description: Detects a single peer sending an excessive number of inv messages, potentially indicating a gossip queue saturation attack.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A composite denial-of-service vulnerability in Zebra's block discovery pipeline allows an unauthenticated remote attacker to permanently halt all new block discovery on a targeted node. This vulnerability, present in Zebra versions prior to 4.4.0, exploits three weaknesses in the gossip, syncer, and download subsystems. The attack is initiated from a single TCP connection, creating a monotonically growing block deficit that never self-heals. This vulnerability allows an attacker to suppress both block discovery paths simultaneously, causing the node to fall permanently behind the chain tip. The discovery of this vulnerability was reported through a coordinated disclosure process by Zebra the researcher.

## Attack Chain

1. Attacker establishes a TCP connection to the targeted Zebra node.
2. Attacker floods the node with a high volume of `inv` messages containing fake block hashes.
3. The gossip download queue on the target node becomes saturated due to the lack of per-connection rate limits on `inv` messages.
4. Legitimate block announcements from honest peers are dropped without warning, preventing normal block discovery via gossip.
5. Attacker sends `FindBlocks` requests to the target node, attempting to trigger the syncer path.
6. Attacker responds to `FindBlocks` requests with empty `inv` messages, degrading the syncer path.
7. When the target node attempts to download blocks, the attacker responds with `NotFound` messages.
8. The target node permanently falls behind the chain tip, requiring operator intervention to recover due to the suppression of both block discovery paths.

## Impact

Successful exploitation of this vulnerability results in a permanent denial-of-service condition. The targeted Zebra node falls behind the chain tip and ceases to discover new blocks, effectively halting its participation in the network. The attack is unauthenticated and requires only a single TCP connection, making it easy to execute. Any Zebra node reachable over the peer-to-peer network is potentially vulnerable. Recovery requires manual intervention by the node operator.

## Recommendation

- Upgrade to Zebra version 4.4.0 or later to patch CVE-2026-44499, as the fix drops connections that send empty responses to `FindBlocks` and `FindHeaders` messages.
- Deploy the Sigma rule "Detect Zebra Syncer Path Degradation" to identify suspicious connections sending empty responses to `FindBlocks` and `FindHeaders` messages.
- Monitor network connections for excessive `inv` message traffic from single peers to detect potential gossip queue saturation attacks.
- Review firewall logs for unusual connection patterns targeting Zebra nodes, indicative of potential reconnaissance or exploitation attempts.
