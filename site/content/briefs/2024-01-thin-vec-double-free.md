---
title: thin-vec Double Free / Use-After-Free Vulnerability
slug: 2024-01-thin-vec-double-free
description: A double free/use-after-free vulnerability exists in the `thin_vec` crate before version 0.2.16, specifically in the `IntoIter::drop` and `ThinVec::clear` implementations, which can be triggered via a panic during element deallocation, leading to memory corruption and potential arbitrary code execution.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - use-after-free
  - double-free
  - memory-corruption
  - rust
  - thin-vec
products:
  - thin-vec
references:
  - https://github.com/advisories/GHSA-xphw-cqx3-667j
rules:
  - title: Detect Panic in Drop Implementation (Generic)
    description: Detects a panic occurring within a drop implementation in Rust code, which can potentially lead to use-after-free or double-free vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
  - title: Detect ThinVec Usage Prior to Version 0.2.16
    description: Detects the use of the `thin-vec` crate in Rust projects with versions prior to 0.2.16 by analyzing Cargo.lock files.
    platform: sigma
    severity: low
    tactics:
      - vulnerability
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A double free/use-after-free vulnerability has been identified in the `thin_vec` crate, affecting versions prior to 0.2.16. The vulnerability resides in the `IntoIter::drop` and `ThinVec::clear` implementations. The root cause is a failure to properly handle panics during element deallocation, leading to a double free when the container is dropped again during stack unwinding. This vulnerability can be triggered using safe Rust code, without requiring `unsafe` blocks. Miri and AddressSanitizer (ASAN) have confirmed the undefined behavior. Exploitation can lead to memory corruption and, when combined with `Box<dyn Trait>` types, potentially arbitrary code execution through heap spray and vtable hijacking. Defenders should be aware of the risk associated with using vulnerable versions of the `thin_vec` crate.

## Attack Chain

1. An application uses the `thin_vec` crate version prior to 0.2.16.
2. The application creates a `ThinVec` containing heap-owning types like `String`, `Vec`, or `Box`.
3. Either `into_iter()` is called, and the iterator is dropped before complete consumption, or `clear()` is directly invoked on the `ThinVec`.
4. During the deallocation of elements (either in `IntoIter::drop` or `ThinVec::clear`), the `Drop` implementation of one of the elements triggers a panic.
5. Due to the panic, the `set_len(0)` function is not executed, leaving the `ThinVec` with an incorrect length.
6. The `ThinVec` is dropped again during stack unwinding (in the `IntoIter::drop` case) or when it goes out of scope (in the `ThinVec::clear` case).
7. The already-freed memory is freed again, resulting in a double free or use-after-free.
8. If combined with `Box<dyn Trait>` types, an attacker might be able to reclaim the freed memory with a fake vtable via heap spraying, potentially leading to arbitrary code execution.

## Impact

This vulnerability can lead to memory corruption and denial of service. If the freed memory is reclaimed by an attacker, it could lead to arbitrary code execution, especially when combined with `Box<dyn Trait>` types. The vulnerability affects all code using the `thin_vec` crate prior to version 0.2.16. Successful exploitation requires specific conditions to be met, including the presence of heap-owning types in the `ThinVec` and a panic occurring during the `Drop` implementation of an element.

## Recommendation

*   Upgrade the `thin-vec` crate to version 0.2.16 or later to remediate the vulnerability ([https://github.com/advisories/GHSA-xphw-cqx3-667j](https://github.com/advisories/GHSA-xphw-cqx3-667j)).
*   If upgrading is not immediately feasible, carefully review the `Drop` implementations of types stored in `ThinVec` to ensure they cannot panic.
*   Monitor application logs for unexpected panics during the deallocation of `ThinVec` elements.
