---
title: rust-openssl Stack Buffer Overflow Vulnerability
slug: 2024-01-03-rust-openssl-buffer-overflow
description: The rust-openssl crate is vulnerable to a stack-based buffer overflow (CVE-2026-41681) where the `EVP_DigestFinal()` function writes beyond the allocated buffer, potentially corrupting the stack, affecting versions >= 0.10.39 and < 0.10.78.
date: "2024-01-03T12:00:00Z"
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

The `rust-openssl` crate, a Rust wrapper for the OpenSSL library, is susceptible to a critical vulnerability (CVE-2026-41681) stemming from a buffer overflow within the `MdCtxRef::digest_final()` function. This flaw arises because `EVP_DigestFinal()` unconditionally writes `EVP_MD_CTX_size(ctx)` bytes to the provided output buffer (`out`), without verifying if the buffer's allocated size is sufficient. Consequently, if `out` is smaller than the size dictated by `EVP_MD_CTX_size(ctx)`, a…
