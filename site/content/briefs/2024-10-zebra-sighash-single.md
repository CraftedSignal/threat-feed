---
title: Zebra Consensus Failure due to Improper SIGHASH_SINGLE Validation
slug: 2024-10-zebra-sighash-single
description: Zebra 4.4.0 failed to enforce a ZIP-244 consensus rule for V5 transparent transactions, potentially leading to a consensus split with zcashd nodes if an input is signed with `SIGHASH_SINGLE` and there is no corresponding output.
date: "2024-10-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - consensus failure
  - signature validation
  - network partition
vendors:
  - Zcash Foundation
products:
  - zebra
  - zebra-script
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: System Availability
    technique_id: T1496
    technique_name: Resource Hijacking
references:
  - https://github.com/advisories/GHSA-pvmv-cwg8-v6c8
rules:
  - title: Detect Zebra SIGHASH_SINGLE Consensus Divergence - High Input Count, Low Output Count
    description: Detects a transaction with a high number of inputs relative to outputs, which could be indicative of an attempt to exploit the Zebra SIGHASH_SINGLE vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1496
    data_sources:
      - network_connection
      - zebrad
  - title: Detect Zebra SIGHASH_SINGLE Consensus Divergence - V5 Transactions
    description: Detects version 5 transactions, which are required for the SIGHASH_SINGLE vulnerability in Zebra.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1496
    data_sources:
      - network_connection
      - zebrad
rules_count: 2
---

Zebra version 4.4.0 improperly validates V5 transparent transactions using the `SIGHASH_SINGLE` signature flag.  Specifically, it fails to enforce a ZIP-244 consensus rule that requires validation to fail when an input is signed with `SIGHASH_SINGLE` and there is no transparent output at the same index.  Instead, Zebra asks the underlying sighash library to compute a digest, resulting in a digest over an empty output set. This divergence from `zcashd`, which correctly rejects such transactions, could allow an attacker to create a consensus split between Zebra and `zcashd` nodes.  The vulnerability exists due to a missed check in Zebra's V5 sighash callback, which calls `librustzcash`'s ZIP-244 implementation.  The issue was addressed in Zebra 4.4.1.

## Attack Chain

1.  Attacker crafts a V5 transaction with two or more transparent inputs.
2.  The crafted transaction includes fewer transparent outputs than inputs.
3.  The attacker signs an input whose index has no matching output (`vout` entry) with `SIGHASH_SINGLE` (0x03) or `SIGHASH_SINGLE|ANYONECANPAY` (0x83).
4.  Zebra's sighash callback incorrectly computes a digest for the invalid input using `librustzcash`, rather than failing the validation.
5.  The attacker broadcasts the malicious transaction to the Zcash network.
6.  Zebra nodes verify the transaction's transparent script using the incorrectly computed digest and accept the transaction (and any block containing it).
7.  `zcashd` nodes reject the transaction due to the invalid `SIGHASH_SINGLE` signature.
8.  This divergence creates a consensus split, potentially isolating Zebra nodes from the rest of the network.

## Impact

This consensus failure could lead to network partitioning, service disruption, and potential double-spend attacks against affected Zebra nodes. While the impact is currently mitigated by the dominance of `zcashd` among miners, a successful attack could still disrupt services relying on Zebra nodes, cause financial losses for affected users, and damage the reputation of the Zebra project.

## Recommendation

*   Upgrade to Zebra version 4.4.1 or later immediately to remediate the vulnerability.
*   Monitor network traffic for unusual transaction patterns, especially V5 transactions with `SIGHASH_SINGLE` signatures.
*   Deploy the Sigma rules in this brief to your SIEM to detect potential exploitation attempts based on transaction characteristics.
*   Review the fix in Zebra 4.4.1 (GHSA-pvmv-cwg8-v6c8) to understand the corrected validation logic.
