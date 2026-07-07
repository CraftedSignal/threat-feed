---
title: Zebra Block Suppression Vulnerability (CVE-2026-52736) via P2P Body Poisoning
slug: 2026-07-zebra-block-suppression
description: A remote unauthenticated attacker can exploit CVE-2026-52736 in Zebra's `zebrad` node (versions up to and including `v4.4.1`) to permanently stall a targeted blockchain node by poisoning its sent-hash cache, leading to a denial of service.
date: "2026-07-03T11:34:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - blockchain
  - denial-of-service
  - network
  - vulnerability
vendors:
  - Zebra
products:
  - zebrad <= 4.4.1
  - zebra-state <= 6.0.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote unauthenticated peer can deliver a poisoned block body that shares a header hash with a later valid canonical block.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The node cannot advance past that height until restart or a reorg event. The node is stuck at height N-1. The node diverges from the network tip; downstream consumers... see a stalled chain.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4m69-67m6-prqp
---

A high-severity vulnerability, CVE-2026-52736, affects Zebra's `zebrad` blockchain nodes, specifically versions up to `v4.4.1`, as well as `zebra-state` up to `v6.0.0`. This flaw allows a remote, unauthenticated attacker to conduct a denial-of-service attack against a target node by exploiting a caching issue in how `zebrad` handles block hashes. By leveraging coinbase scriptSig malleability (ZIP-244 `txid_v5`) to create a poisoned block body with the same header hash as a legitimate canonical block, an attacker can cause the node to cache the hash and then reject the actual valid block as a duplicate. This leads to the node permanently stalling at a specific block height, diverging from the network tip, and preventing downstream services like lightwalletd, wallets, and explorers from advancing. The attack requires winning a propagation race to deliver the poisoned block before honest peers deliver the canonical one, which a well-positioned attacker can reliably achieve.

## Attack Chain

1.  Attacker observes a new block header from any peer on the network.
2.  Attacker constructs a poisoned block body that has an identical header hash to the observed block, achieved by mutating the coinbase `scriptSig` extra-data section.
3.  Attacker advertises the hash of this specially crafted block to the target Zebra node via an `inv` (inventory) message over the P2P network.
4.  The target Zebra node requests the advertised block via a `getdata` message, and the attacker serves the poisoned body.
5.  Zebra adds the block hash to its `non_finalized_block_write_sent_hashes` cache before completing contextual validation of the block body.
6.  The write task within Zebra subsequently rejects the poisoned body due to an `auth_data_root` mismatch (specifically, `block_commitment_is_valid_for_chain_history` fails), but the hash is not removed from the `non_finalized_block_write_sent_hashes` cache.
7.  When the valid, canonical block later arrives from honest peers or an RPC connection, Zebra's `queue_and_commit_to_non_finalized_state` function sees the hash already in the cache and erroneously treats it as a duplicate, returning `KnownBlock::WriteChannel`.
8.  The target Zebra node fails to advance past the affected block height (N-1), becoming permanently stalled until a manual restart (which clears the in-memory cache) or a rare chain reorg event occurs.

## Impact

Successful exploitation of CVE-2026-52736 leads to a permanent denial of service for the targeted Zebra node, causing it to diverge from the main blockchain network. This renders the node unable to process new blocks, effectively stalling its operation. Downstream services and applications that rely on the affected node, such as lightwallets, block explorers, and potentially mining infrastructure, will experience service degradation or complete outages due to an inability to access up-to-date blockchain data. Recovery from this attack typically requires manual intervention, specifically restarting the `zebrad` process to clear the in-memory sent-hash cache, or waiting for an unlikely chain reorg at the stalled height. There is no information on specific victim counts or sectors, but any organization operating vulnerable Zebra nodes is at risk.

## Recommendation

*   Immediately patch all `zebrad` nodes to version `v4.4.2` or later to remediate CVE-2026-52736, which includes a fix for removing stale entries from the sent-hash cache.
*   While not a complete solution for CVE-2026-52736, consider reducing the `network.peerset_initial_target_size` configuration to narrow the attack surface by limiting the number of inbound P2P connections.
*   Be prepared to restart `zebrad` nodes if they stall at a specific block height, as this is the primary recovery mechanism to clear the in-memory `non_finalized_block_write_sent_hashes` cache.
