---
title: smallbitvec Integer Overflow Leads to Heap Buffer Overflow
slug: 2024-01-23-smallbitvec-overflow
description: An integer overflow in the `smallbitvec` crate leads to an undersized heap allocation, enabling heap buffer overflows through safe APIs, affecting versions 1.0.1 through 2.6.0.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - integer-overflow
  - heap-buffer-overflow
  - memory-corruption
vendors:
  - rust
products:
  - smallbitvec (>= 1.0.1, <= 2.6.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-97wc-2hqc-cjgr
rules:
  - title: Detect `smallbitvec` Integer Overflow via Large Capacity
    description: Detects attempts to trigger an integer overflow in `smallbitvec` by instantiating a `SmallBitVec` with an excessively large capacity value, specifically `usize::MAX`.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect `smallbitvec` Integer Overflow via Large Reserve
    description: Detects attempts to trigger an integer overflow in `smallbitvec` by reserving a large amount of memory using the `reserve` function.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `smallbitvec` crate in Rust versions 1.0.1 through 2.6.0 is vulnerable to an integer overflow within the internal capacity calculation, specifically in the `buffer_len` function. This function computes the required buffer size based on the provided capacity (`cap`). When `cap` approaches `usize::MAX`, the addition `cap + bits_per_storage() - 1` can overflow in release builds, resulting in a wraparound due to Rust’s default wrapping semantics for integer overflow in optimized builds. This overflow leads to an undersized heap allocation. Subsequent safe API calls like `set`, `push`, and `reserve` rely on this corrupted metadata, leading to out-of-bounds memory access and heap buffer overflows. This vulnerability allows memory corruption without requiring the use of `unsafe` code by the caller.

## Attack Chain

1. A `SmallBitVec` is instantiated using a large capacity (e.g., `usize::MAX` in `from_elem` or a large value passed to `reserve`).
2. The `buffer_len(cap)` function is called internally to calculate the required buffer size.
3. The addition within `buffer_len(cap)` overflows, resulting in a smaller-than-expected value.
4. The backing storage is allocated based on the overflowed, smaller size.
5. Internal metadata (logical length/capacity) is set based on the original, large capacity value, creating a mismatch between metadata and actual buffer size.
6. A safe API call (e.g., `set`, `push`, `reserve`) is invoked, using the corrupted metadata for index calculations.
7. The index calculation assumes sufficient backing storage based on the logical length/capacity, which is incorrect.
8. The operation reaches unsafe internal code paths, leading to out-of-bounds memory access and a heap buffer overflow, resulting in undefined behavior.

## Impact

Successful exploitation of this vulnerability results in a heap buffer overflow, potentially leading to arbitrary code execution. The vulnerability is detectable with tools like ASAN (AddressSanitizer) and Miri. While the exact number of affected projects is unknown, any project using vulnerable versions of the `smallbitvec` crate is susceptible to this vulnerability. This issue allows for memory corruption and could compromise the integrity and security of applications utilizing the affected crate.

## Recommendation

*   Upgrade the `smallbitvec` crate to a version greater than 2.6.0 to remediate CVE-2026-44983.
*   Implement runtime checks on capacity values before allocating memory to prevent integer overflows.
*   Deploy the Sigma rule "Detect `smallbitvec` Integer Overflow via Large Capacity" to detect attempts to trigger the vulnerability through excessively large capacity values in `SmallBitVec` instantiation.
