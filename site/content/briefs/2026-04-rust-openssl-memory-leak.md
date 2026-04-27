---
title: rust-openssl Unchecked Callback Length Memory Leak
slug: 2026-04-rust-openssl-memory-leak
description: The rust-openssl crate versions 0.9.24 prior to 0.10.78 are vulnerable to memory leaks due to unchecked callback lengths in PSK/cookie trampolines, potentially leading to buffer overflows.
date: "2026-04-23T12:00:00Z"
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

The `rust-openssl` crate, a Rust wrapper for the OpenSSL library, is susceptible to a high-severity vulnerability due to unchecked callback lengths within the FFI trampolines used by several functions related to PSK (Pre-Shared Key) and cookie generation. Specifically, versions 0.9.24 up to (but not including) 0.10.78 are affected. The vulnerable functions include `SslContextBuilder::set_psk_client_callback`, `set_psk_server_callback`, `set_cookie_generate_cb`, and…
