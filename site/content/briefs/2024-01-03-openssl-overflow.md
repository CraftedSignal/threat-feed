---
title: Heap/Stack Overflow in rust-openssl with OpenSSL 1.1.x
slug: 2024-01-03-openssl-overflow
description: The rust-openssl crate's `Deriver::derive` and `PkeyCtxRef::derive` functions can cause heap/stack overflows when used with OpenSSL 1.1.x due to insufficient buffer length validation in X25519, X448, DH, and HKDF-extract, affecting rust-openssl versions >= 0.9.27 and < 0.10.78.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openssl
  - buffer-overflow
  - rust
  - cryptography
vendors:
  - OpenSSL
products:
  - openssl
references:
  - https://github.com/advisories/GHSA-pqf5-4pqq-29f5
rules:
  - title: Detect EVP_PKEY_derive Usage with potentially undersized buffer
    description: Detects calls to EVP_PKEY_derive where the output buffer size is smaller than expected for X25519, X448, DH, or HKDF-extract on systems with OpenSSL 1.1.x.  This is a preventative measure, as direct detection of the overflow is difficult.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect rust-openssl usage with OpenSSL 1.1.x Libraries
    description: Detects process creation where rust-openssl binaries are used, and OpenSSL libraries from the 1.1.x branch are loaded dynamically. This aims to catch processes that may be vulnerable to the overflow issue.
    platform: sigma
    severity: low
    tactics:
      - vulnerability
    data_sources:
      - image_load
      - linux
rules_count: 2
---

The `rust-openssl` crate, specifically the `Deriver::derive` and `PkeyCtxRef::derive` functions, is vulnerable to a heap/stack overflow when used in conjunction with OpenSSL version 1.1.x. This occurs because the `EVP_PKEY_derive` function in OpenSSL 1.1.x fails to properly validate the input buffer length when used with X25519, X448, DH, and HKDF-extract. These key derivation functions unconditionally write the full shared secret (32/56/prime-size bytes) regardless of the buffer size provided by the caller, leading to a buffer overflow if the provided slice is too small. This vulnerability affects rust-openssl versions >= 0.9.27 and < 0.10.78. This vulnerability is mitigated in OpenSSL 3.x because the providers check buffer length.

## Attack Chain

1. An attacker crafts a malicious application using the `rust-openssl` crate.
2. The application uses `Deriver::derive` or `PkeyCtxRef::derive` with an X25519, X448, DH, or HKDF-extract key agreement algorithm.
3. The application provides a buffer smaller than the expected output size of the key derivation function (32 bytes for X25519, 56 bytes for X448, prime-size bytes for DH).
4. The `EVP_PKEY_derive` function in OpenSSL 1.1.x is called without proper buffer length validation.
5. The key derivation function writes the full shared secret to the undersized buffer.
6. A heap or stack buffer overflow occurs, overwriting adjacent memory.
7. The attacker gains control of the application's execution flow.
8. The attacker executes arbitrary code on the target system.

## Impact

Successful exploitation of this vulnerability can lead to arbitrary code execution within the context of the vulnerable application. This could allow an attacker to gain complete control of the affected system. The number of victims depends on the prevalence of vulnerable `rust-openssl` versions being used with OpenSSL 1.1.x. Sectors that rely on `rust-openssl` for cryptographic operations are at higher risk.

## Recommendation

*   Upgrade the `rust-openssl` crate to version >= 0.10.78 to patch the vulnerability (see Overview).
*   If upgrading `rust-openssl` is not immediately feasible, ensure that OpenSSL is upgraded to version 3.x, where the buffer length is checked (see Overview).
*   Implement runtime checks to validate buffer lengths before calling `Deriver::derive` and `PkeyCtxRef::derive` when using X25519, X448, DH, or HKDF-extract (see Attack Chain).
*   Deploy the Sigma rule provided below to detect potential exploitation attempts (see Rules).
