---
title: Plonky3 Challenger Transcript Malleability and Challenge Entropy Loss
slug: 2026-05-plonky3-challenger
description: The p3-challenger rust package is vulnerable to transcript malleability and challenge entropy loss, allowing attackers to craft distinct transcripts that produce identical challenges, breaking the binding property of Fiat-Shamir due to partial-chunk aliasing, non-injective squeeze, and high-bit truncation.
date: "2026-05-21T20:25:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - transcript-malleability
  - challenge-entropy
  - cryptography
  - rust
vendors:
  - rust
products:
  - p3-challenger
references:
  - https://github.com/advisories/GHSA-vj64-rjf3-w3v7
  - CVE-2026-46654
rules:
  - title: Detect CVE-2026-46654 Attempt - Partial Chunk Aliasing via Reduce32
    description: Detects potential attempts to exploit CVE-2026-46654 by observing patterns indicative of partial chunk aliasing in cryptographic protocols using vulnerable versions of p3-challenger.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.006
    data_sources:
      - process_creation
      - linux
  - title: Detect CVE-2026-46654 Attempt - Squeeze Function Manipulation
    description: Detects potential exploitation of CVE-2026-46654 by identifying suspicious calls to the squeeze function within p3-challenger that could indicate non-injective squeezing.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `p3-challenger` Rust package, specifically versions prior to 0.4.3 and versions between 0.5.0 and 0.5.3, contains vulnerabilities that can be exploited to manipulate cryptographic transcripts. These vulnerabilities stem from issues in the `MultiField32Challenger::duplexing` function within `challenger/src/multi_field_challenger.rs`. An attacker with control over prover-side observations can exploit these weaknesses to craft distinct transcripts that generate identical challenges, thereby breaking the binding property of the Fiat-Shamir transform. This impacts the integrity of cryptographic protocols that rely on the challenger to produce unpredictable challenges based on previous interactions. The vulnerabilities include partial-chunk aliasing during absorption, non-injective squeeze functions, and high-bit truncation during digest observation. These flaws can lead to weakened entropy and potential for selective forgery.

## Attack Chain

1. Attacker gains control over prover-side observations in a cryptographic protocol using `p3-challenger`.
2. The prover provides an initial observation `[x]` to the `MultiField32Challenger`.
3. Due to partial-chunk aliasing (CVE-2026-46654), the attacker can manipulate the input by extending the observation with zeros `[x, 0, ..., 0]` without affecting the sponge state, because the `reduce_32` function doesn't account for length.
4. The `duplexing()` function processes the input using `reduce_32`, leading to an equivalent sponge state for both `[x]` and `[x, 0, ..., 0]`.
5. The challenger proceeds to squeeze the sponge state to generate a challenge.  Due to the non-injective squeeze vulnerability, distinct PF values whose base-2^64 digits differ only in their upper 33 bits produce identical F challenge sequences.
6. The attacker can also observe Hash/MerkleCap values; high-bit truncation discards the top bits. For BN254, only 192 bits are considered, allowing the attacker to manipulate bits 192-253 without affecting challenges.
7. The identical sponge state results in the same challenge being generated, regardless of the attacker's manipulation of the transcript.
8. The attacker exploits the compromised challenge to forge a proof or selectively alter protocol behavior.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to undermine the security of cryptographic protocols relying on the `p3-challenger` package. By crafting transcripts that yield identical challenges, attackers can forge proofs, selectively alter protocol behavior, or bypass security mechanisms designed to prevent malicious activity. The impact is significant in zero-knowledge proof systems, verifiable computation, and other cryptographic applications where the integrity of the challenger is crucial. These vulnerabilities affect any application using the flawed versions of `p3-challenger`, potentially compromising the security of numerous systems that depend on these cryptographic primitives.

## Recommendation

*   Upgrade to `p3-challenger` version 0.4.3 or 0.5.3 or later to remediate CVE-2026-46654.
*   Implement input validation to prevent partial-chunk aliasing, ensuring that input buffers are properly padded and length-marked before processing with `reduce_32`.
*   Review and harden the squeeze function to guarantee injectivity, ensuring distinct PF rate cells yield distinct F challenge sequences, to prevent non-injective squeezes.
*   Ensure that all bits of absorbed elements influence the sponge state, addressing high-bit truncation, especially for fields whose bit-width is not a multiple of 64.
