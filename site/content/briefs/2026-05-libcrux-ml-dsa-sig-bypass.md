---
title: libcrux-ml-dsa Signature Verification Bypass Vulnerability
slug: 2026-05-libcrux-ml-dsa-sig-bypass
description: The AVX2 implementation of ML-DSA verification in libcrux-ml-dsa mishandles an edge case in the `use_hint` function, potentially allowing an attacker to craft an invalid signature that is accepted by the verifier if the AVX2 implementation is used.
date: "2026-05-19T16:21:24Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - signature-bypass
  - vulnerability
vendors:
  - Rust
products:
  - libcrux-ml-dsa (< 0.0.9)
references:
  - https://github.com/advisories/GHSA-fhvh-vw7h-9xf3
rules:
  - title: Detect libcrux-ml-dsa Signature Verification Bypass Attempt (Process)
    description: Detects potential attempts to exploit the libcrux-ml-dsa signature verification bypass by monitoring process arguments for suspicious patterns.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - process_creation
      - linux
  - title: Detect libcrux-ml-dsa Signature Verification Bypass Attempt (File)
    description: Detects potential attempts to exploit the libcrux-ml-dsa signature verification bypass by monitoring file events for suspicious access to the vulnerable library.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The `libcrux-ml-dsa` library, a Rust implementation of ML-DSA (a post-quantum signature scheme), contains a vulnerability in its AVX2 implementation of signature verification. Specifically, the `use_hint` function incorrectly handles an edge case. This flaw allows an attacker to potentially bypass signature verification and forge valid signatures under a maliciously generated verification key when the AVX2 implementation is utilized. This vulnerability affects versions prior to 0.0.9. Defenders should ensure the library is updated to version 0.0.9 or later to mitigate the risk of signature forgery.

## Attack Chain

1.  Attacker analyzes the vulnerable `use_hint` function within the AVX2 implementation of `libcrux-ml-dsa` versions prior to 0.0.9.
2.  The attacker identifies the specific edge case in the `use_hint` function that is mishandled.
3.  Attacker crafts a malicious ML-DSA signature that exploits the identified edge case.
4.  The attacker generates a malicious verification key designed to amplify the vulnerability.
5.  Attacker targets a system or application that relies on `libcrux-ml-dsa` for signature verification using the AVX2 implementation.
6.  The vulnerable `libcrux-ml-dsa` library attempts to verify the crafted signature using the malicious verification key.
7.  Due to the mishandled edge case, the `use_hint` function incorrectly accepts the invalid signature as valid.
8.  The targeted system or application trusts the forged signature, leading to unauthorized access or execution of malicious code.

## Impact

Successful exploitation of this vulnerability allows an attacker to bypass signature verification mechanisms in applications using `libcrux-ml-dsa` library prior to version 0.0.9. This could lead to complete system compromise, unauthorized code execution, or data manipulation. While the exact number of affected systems is unknown, any application utilizing the vulnerable library for signature verification is at risk.

## Recommendation

*   Upgrade `rust/libcrux-ml-dsa` to version `0.0.9` or later to patch the vulnerability (reference: Mitigation section).
*   Monitor applications using `libcrux-ml-dsa` for unexpected behavior related to signature verification, such as unauthorized access attempts (reference: Overview).
