---
title: Nimiq Block Skip Block Quorum Bypass Vulnerability
slug: 2024-01-nimiq-block-quorum-bypass
description: A vulnerability exists in Nimiq Block's SkipBlockProof verification process, allowing attackers to bypass quorum checks by manipulating MultiSignature signers with out-of-range indices, potentially compromising blockchain integrity, and affecting rust/nimiq-block versions 0.2.0 and earlier.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
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

A critical vulnerability has been identified in the Nimiq Block's `SkipBlockProof::verify` function within the rust-albatross core. This vulnerability stems from the way the quorum check is performed. The vulnerability lies in the ability to craft `MultiSignature.signers` that contain out-of-range indices spaced by 65536, inflating the `len()` calculation but colliding onto the same in-range `u16` slot during aggregation due to truncation. The vulnerability affects `rust/nimiq-block` versions `<= 0.2.0`. Successful exploitation allows a malicious validator with significantly fewer than the required `2f+1` signer slots to pass skip block proof verification. This bypasses the intended security mechanisms, potentially undermining the blockchain's consensus and integrity.

## Attack Chain

1.  Attacker identifies a Nimiq Block instance running a vulnerable version (<= 0.2.0) of the `rust/nimiq-block` package.
2.  The attacker crafts a malicious `MultiSignature.signers` payload.
3.  The malicious payload contains out-of-range indices spaced by 65536. These indices are specifically designed to inflate the `BitSet.len()` calculation used in the quorum check.
4.  During verification within `SkipBlockProof::verify`, the `usize` indices are cast to `u16` (`slot as u16`) for slot lookup.
5.  Due to the `u16` truncation, the out-of-range indices collide onto the same in-range slot. This creates an artificial aggregation of signatures.
6.  The attacker multiplies a single BLS signature by a factor to match the inflated `len()` value.
7.  The manipulated `SkipBlockProof` passes the quorum check due to the inflated `len()` and signature aggregation.
8.  The malicious skip block is accepted, potentially leading to consensus manipulation or other attacks on the blockchain.

## Impact

Successful exploitation of this vulnerability allows a malicious validator to bypass the standard quorum requirements for skip block proof verification. This means that a single compromised validator or a small group of colluding validators can inject fraudulent blocks into the blockchain, potentially leading to double-spending, denial-of-service, or other attacks that compromise the integrity and availability of the Nimiq blockchain. Given the severity of these potential outcomes, this vulnerability poses a critical risk to any system relying on affected versions of Nimiq Block.

## Recommendation

*   Upgrade to `rust/nimiq-block` version `1.3.0` or later, which includes the fix for [CVE-2026-33471](https://github.com/advisories/GHSA-6973-8887-87ff).
*   Monitor network traffic for anomalies related to skip block submissions, focusing on unusually large `MultiSignature.signers` payloads with indices spaced by multiples of 65536. Create a network monitoring rule.
