---
title: Nimiq Primitives Trie Chunk Processing Denial-of-Service (CVE-2026-46545)
slug: 2026-05-nimiq-trie-dos
description: A remote denial-of-service vulnerability (CVE-2026-46545) exists in Nimiq primitives where an unauthenticated peer can send a malicious chunk with an empty key, leading to a panic when `put_raw` attempts to store a value at the root node, causing the node process to abort.
date: "2026-05-21T19:51:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - rust
vendors:
  - Nimiq
products:
  - nimiq-primitives (< 1.5.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-mw3q-r9wh-h2ff
  - https://github.com/nimiq/core-rs-albatross/pull/3762
  - https://github.com/nimiq/core-rs-albatross/blob/albatross/primitives/trie/src/trie.rs
rules:
  - title: Detect Nimiq Trie Denial of Service Attempt via State Sync
    description: Detects potential denial of service attempts by identifying unusual patterns in state synchronization requests which could indicate an attempt to trigger CVE-2026-46545.
    platform: sigma
    severity: low
    tactics:
      - cve-2026-46545
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
  - title: Detect Panic in Nimiq Primitives Due to Root Value Error
    description: Detects a panic within Nimiq primitives related to attempting to store a value at the root node, indicative of CVE-2026-46545.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-46545
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A remote, unauthenticated denial-of-service vulnerability has been identified in the `nimiq-primitives` library, specifically affecting the `MerkleRadixTrie::put_chunk` function. This vulnerability allows any state-sync peer to crash a node performing state synchronization, including freshly joining nodes and those recovering from data loss. The vulnerability occurs because a malicious peer can respond to a `RequestChunk` with a `ResponseChunk::Chunk` whose first `TrieItem.key` is the empty (ROOT) key. When `put_raw` tries to store a value at the root node, it calls `TrieNode::put_value(...).unwrap()`, which returns `Err(RootCantHaveValue)` and panics, aborting the node process. This vulnerability impacts any node running state sync against untrusted peers. The affected package is `rust/nimiq-primitives` versions prior to 1.5.0. This issue is tracked as CVE-2026-46545.

## Attack Chain

1. A node initiates state synchronization with peers.
2. A malicious peer receives a `RequestChunk` message from the victim node.
3. The malicious peer crafts a `ResponseChunk::Chunk` message.
4. The crafted `ResponseChunk::Chunk` message contains a `TrieItem.key` with an empty (ROOT) key as its first element.
5. The victim node receives the malicious chunk and processes it using `MerkleRadixTrie::put_chunk` (around line 819 in `primitives/trie/src/trie.rs`).
6. During processing, the `put_raw` function (around line 351 in `primitives/trie/src/trie.rs`) attempts to store a value at the root node.
7. `TrieNode::put_value(...).unwrap()` returns `Err(RootCantHaveValue)`.
8. The node process panics and aborts, resulting in a denial-of-service.

## Impact

This vulnerability can lead to a denial-of-service condition for nodes running state synchronization against untrusted peers. This includes freshly joining nodes performing initial download and existing nodes recovering from data loss. Successful exploitation results in the crashing of the victim node, disrupting its ability to participate in the network. The vulnerability can be triggered without authentication and is not subject to rate limiting, making it highly impactful.

## Recommendation

*   Upgrade to `nimiq-primitives` version 1.5.0 or later to patch CVE-2026-46545.
*   Monitor network traffic for unexpected state synchronization behavior with untrusted peers.
*   Implement rate limiting and authentication mechanisms for state synchronization requests where feasible.
