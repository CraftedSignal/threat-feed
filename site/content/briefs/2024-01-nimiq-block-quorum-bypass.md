---
title: Nimiq Block Skip Block Quorum Bypass Vulnerability
slug: 2024-01-nimiq-block-quorum-bypass
description: A vulnerability exists in Nimiq Block's SkipBlockProof verification process, allowing attackers to bypass quorum checks by manipulating MultiSignature signers with out-of-range indices, potentially compromising blockchain integrity, and affecting rust/nimiq-block versions 0.2.0 and earlier.
date: "2024-01-02T12:00:00Z"
severities:
  - medium
tags:
  - blockchain
  - quorum bypass
  - nimiq
  - rust
vendors:
  - Nimiq
products:
  - nimiq-block
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1210
    technique_name: Exploitation of Vulnerability
references:
  - https://github.com/advisories/GHSA-6973-8887-87ff
  - https://github.com/nimiq/core-rs-albatross/pull/3657
  - https://github.com/nimiq/core-rs-albatross/releases/tag/v1.3.0
rules:
  - title: Detect Suspiciously Large MultiSignature Signers Payload
    description: Detects unusually large MultiSignature signers payloads that could indicate an attempt to exploit the quorum bypass vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1210
    data_sources:
      - network_connection
      - linux
  - title: Detect Skip Block Proof with High Index Variance
    description: Detects skip block proofs where the variance between signer indices is unusually high, potentially indicating an attempt to manipulate BitSet.len().
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1210
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A critical vulnerability has been identified in the Nimiq Block's `SkipBlockProof::verify` function within the rust-albatross core. This vulnerability stems from the way the quorum check is performed. The vulnerability lies in the ability to craft `MultiSignature.signers` that contain out-of-range indices spaced by 65536, inflating the `len()` calculation but colliding onto the same in-range `u16` slot during aggregation due to truncation. The vulnerability affects `rust/nimiq-block` versions…
