---
title: rust-openssl Stack Buffer Overflow Vulnerability
slug: 2024-01-03-rust-openssl-buffer-overflow
description: The rust-openssl crate is vulnerable to a stack-based buffer overflow (CVE-2026-41681) where the `EVP_DigestFinal()` function writes beyond the allocated buffer, potentially corrupting the stack, affecting versions >= 0.10.39 and < 0.10.78.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer overflow
  - rust
  - openssl
  - vulnerability
vendors:
  - OpenSSL
products:
  - openssl
references:
  - https://github.com/advisories/GHSA-ghm9-cr32-g9qj
  - https://github.com/rust-openssl/rust-openssl#2608
  - https://github.com/rust-openssl/rust-openssl@826c388
  - https://github.com/rust-openssl/rust-openssl/releases/tag/openssl-v0.10.78
rules:
  - title: Detect EVP_DigestFinal stack buffer overflow
    description: Detects potential stack buffer overflows by monitoring calls to the vulnerable EVP_DigestFinal function without length checks.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect rust-openssl usage
    description: Detects the usage of rust-openssl library.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - image_load
      - linux
rules_count: 2
---

The `rust-openssl` crate, a Rust wrapper for the OpenSSL library, is susceptible to a critical vulnerability (CVE-2026-41681) stemming from a buffer overflow within the `MdCtxRef::digest_final()` function. This flaw arises because `EVP_DigestFinal()` unconditionally writes `EVP_MD_CTX_size(ctx)` bytes to the provided output buffer (`out`), without verifying if the buffer's allocated size is sufficient. Consequently, if `out` is smaller than the size dictated by `EVP_MD_CTX_size(ctx)`, a write-out-of-bounds condition occurs, potentially leading to stack corruption. The vulnerability is reachable from safe Rust code, making it a significant concern for applications utilizing the affected versions of the `rust-openssl` crate. Specifically, versions 0.10.39 up to (but not including) 0.10.78 are affected.

## Attack Chain

1. An attacker crafts a Rust application that utilizes the `rust-openssl` crate.
2. The application initiates a digest operation using `EVP_DigestInit()` to set up the message digest context.
3. The application feeds data into the digest context using `EVP_DigestUpdate()`.
4. The application calls `MdCtxRef::digest_final()` via safe Rust.
5. Internally, `EVP_DigestFinal()` is called without proper bounds checking.
6. `EVP_DigestFinal()` attempts to write `EVP_MD_CTX_size(ctx)` bytes to the `out` buffer.
7. If `out` is smaller than the expected size, a stack-based buffer overflow occurs as data is written beyond the allocated memory region.
8. This overflow overwrites adjacent memory on the stack, potentially corrupting critical program data or control flow structures, leading to crashes or arbitrary code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to potentially achieve arbitrary code execution within the context of the affected application. This could lead to complete system compromise, data breaches, or denial-of-service conditions. Given that the vulnerability is reachable from safe Rust, applications relying on vulnerable versions of the `rust-openssl` crate are at risk. The vulnerability can cause stack corruption, leading to unpredictable behavior and potential application crashes.

## Recommendation

*   Upgrade the `rust-openssl` crate to version 0.10.78 or later to remediate CVE-2026-41681.
*   Implement robust input validation and size checks when using the `rust-openssl` crate, specifically when handling digest operations, to prevent buffer overflows.
