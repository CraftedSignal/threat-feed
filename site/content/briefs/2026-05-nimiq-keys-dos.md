---
title: Nimiq nimiq-keys Ed25519 Signature Length Vulnerability (CVE-2026-40092)
slug: 2026-05-nimiq-keys-dos
description: A malicious network peer can crash a Nimiq full node by publishing a crafted Kademlia DHT record due to unchecked Ed25519 signature length in `TaggedPublicKey::verify` (CVE-2026-40092).
date: "2026-05-15T16:32:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - nimiq
  - signature-validation
vendors:
  - Nimiq
products:
  - nimiq-keys (<= 0.2.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-27w2-87xv-37c6
  - https://github.com/nimiq/core-rs-albatross/pull/3708
  - https://github.com/nimiq/core-rs-albatross/releases/tag/v1.4.0
rules:
  - title: Detect Nimiq Node Crash Due to Invalid Ed25519 Signature Length (Simulated)
    description: Detects a simulated Nimiq node crash by monitoring for process termination events that are immediately preceded by an invalid signature length error. This is a conceptual rule intended to demonstrate a detection strategy since direct monitoring of a Nimiq node is not available. CVE-2026-40092
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Nimiq Node Logging Invalid Ed25519 Signature Length (Simulated)
    description: Detects a simulated Nimiq node logging an invalid Ed25519 signature length error. This is a conceptual rule intended to demonstrate a detection strategy since direct monitoring of a Nimiq node is not available. CVE-2026-40092
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A remote denial-of-service vulnerability exists within the Nimiq `nimiq-keys` component, specifically affecting versions 0.2.0 and earlier. This flaw, identified as CVE-2026-40092, allows a malicious actor on the Nimiq network to deliberately crash a full node. The attack involves crafting a Kademlia Distributed Hash Table (DHT) record that contains a `TaggedSigned<ValidatorRecord, KeyPair>` structure with a malformed signature. Specifically, the signature field must not be exactly 64 bytes in length. The vulnerability lies in the insufficient validation of the signature length within the `TaggedPublicKey::verify` function, which leads to a panic and node crash. This issue was addressed in version 1.4.0 of the `core-rs-albatross` library.

## Attack Chain

1. Attacker crafts a malicious Kademlia DHT record.
2. The record includes a `TaggedSigned<ValidatorRecord, KeyPair>` structure.
3. The signature field within this structure is intentionally set to a length other than 64 bytes.
4. The attacker publishes this crafted DHT record to the Nimiq network.
5. A victim Nimiq full node receives the malicious DHT record.
6. The victim node's DHT verifier processes the record and calls `TaggedSigned::verify`.
7. Inside `TaggedSigned::verify`, the `Ed25519Signature::from_bytes(sig).unwrap()` function is called.
8. Because the signature `sig` is not 64 bytes, `ed25519_zebra::Signature::try_from` fails, causing `unwrap()` to panic, crashing the node.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition for the targeted Nimiq full node. An attacker can repeatedly trigger this crash, potentially disrupting the Nimiq network's stability. The number of affected nodes depends on the attacker's ability to distribute the crafted DHT records across the network. This could impact the availability of the Nimiq network, making it unavailable for legitimate users.

## Recommendation

*   Upgrade to Nimiq `core-rs-albatross` version 1.4.0 or later, which includes the patch for CVE-2026-40092 (see [PR](https://github.com/nimiq/core-rs-albatross/pull/3708) and [v1.4.0](https://github.com/nimiq/core-rs-albatross/releases/tag/v1.4.0)).
*   Implement a network monitoring rule to detect unusual DHT record sizes or malformed signature lengths being propagated across the Nimiq network. While no specific rule is provided, monitoring network traffic for anomalies related to DHT records could provide early warning of exploitation attempts.
