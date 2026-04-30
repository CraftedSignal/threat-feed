---
title: rust-openssl Unchecked Callback Length Memory Leak
slug: 2026-04-rust-openssl-memory-leak
description: The rust-openssl crate versions 0.9.24 prior to 0.10.78 are vulnerable to memory leaks due to unchecked callback lengths in PSK/cookie trampolines, potentially leading to buffer overflows.
date: "2026-04-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rust
  - openssl
  - memory leak
  - buffer overflow
vendors:
  - Rust
products:
  - openssl
references:
  - https://github.com/advisories/GHSA-hppc-g8h3-xhp3
  - https://github.com/rust-openssl/rust-openssl#2607
  - https://github.com/rust-openssl/rust-openssl/releases/tag/openssl-v0.10.78
rules:
  - title: Detect rust-openssl PSK/Cookie Callback Length Mismatch
    description: Detects potential exploitation attempts by identifying inconsistencies between the expected and actual buffer lengths in PSK or Cookie callbacks within rust-openssl applications. This can indicate an attempt to trigger the GHSA-hppc-g8h3-xhp3 vulnerability leading to memory corruption or information disclosure.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect rust-openssl Memory Access Violation
    description: This rule detects potential memory access violations during rust-openssl operations. This may indicate an attempt to exploit vulnerabilities such as GHSA-hppc-g8h3-xhp3, where unchecked callback lengths lead to buffer overflows.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - system
      - linux
rules_count: 2
---

The `rust-openssl` crate, a Rust wrapper for the OpenSSL library, is susceptible to a high-severity vulnerability due to unchecked callback lengths within the FFI trampolines used by several functions related to PSK (Pre-Shared Key) and cookie generation. Specifically, versions 0.9.24 up to (but not including) 0.10.78 are affected. The vulnerable functions include `SslContextBuilder::set_psk_client_callback`, `set_psk_server_callback`, `set_cookie_generate_cb`, and `set_stateless_cookie_generate_cb`. The issue arises because the user-provided closure's returned `usize` (size) value is directly passed to OpenSSL without validation against the size of the `&mut [u8]` buffer provided to the closure, resulting in potential buffer overflows and memory leaks. This allows an attacker to potentially leak adjacent memory regions to a peer.

## Attack Chain

1.  An attacker crafts a malicious application or exploits an existing application using the vulnerable `rust-openssl` crate.
2.  The attacker triggers one of the vulnerable callback functions (`set_psk_client_callback`, `set_psk_server_callback`, `set_cookie_generate_cb`, or `set_stateless_cookie_generate_cb`).
3.  The vulnerable callback function executes the user-provided closure.
4.  The user-provided closure returns a `usize` value indicating the intended length of the data to be written to the output buffer.
5.  The FFI trampoline forwards this `usize` value directly to OpenSSL, bypassing bounds checking against the actual buffer size.
6.  If the returned `usize` exceeds the allocated buffer size, OpenSSL writes beyond the buffer boundary, leading to a buffer overflow.
7.  The buffer overflow allows the attacker to read adjacent memory regions or overwrite data, potentially leaking sensitive information or corrupting program state.
8.  Successful exploitation could lead to information disclosure, denial of service, or potentially arbitrary code execution.

## Impact

Successful exploitation of this vulnerability could lead to information disclosure, denial of service, or potentially arbitrary code execution. Given the widespread use of the `rust-openssl` crate in various applications, the impact could be significant, affecting numerous services and potentially exposing sensitive data. The vulnerability allows for memory leakage to peers which could have broad consequences.

## Recommendation

*   Upgrade to `rust-openssl` version 0.10.78 or later to patch the vulnerability (reference: https://github.com/rust-openssl/rust-openssl/releases/tag/openssl-v0.10.78).
*   Implement input validation and sanitization within user-provided closures to ensure that the returned `usize` value does not exceed the allocated buffer size, mitigating the risk even in vulnerable versions.
