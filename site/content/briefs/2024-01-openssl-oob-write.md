---
title: rust-openssl AES Key Wrap Out-of-Bounds Write Vulnerability
slug: 2024-01-openssl-oob-write
description: The rust-openssl package is vulnerable to an out-of-bounds write due to an incorrect bounds assertion in the `aes::unwrap_key()` function, potentially leading to arbitrary code execution if attacker-controlled buffer sizes are permitted.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openssl
  - aes
  - keywrap
  - oob-write
  - memory-corruption
vendors:
  - OpenSSL
products:
  - openssl
references:
  - https://github.com/advisories/GHSA-8c75-8mhr-p7r9
rules:
  - title: Detect Potential Exploitation of rust-openssl AES Key Wrap OOB Write (Process)
    description: Detects suspicious process executions that may be related to the exploitation of the rust-openssl AES Key Wrap out-of-bounds write vulnerability, based on command-line arguments or process ancestry.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Potential Exploitation of rust-openssl AES Key Wrap OOB Write (Network)
    description: Detects network connections originating from processes potentially exploiting the rust-openssl AES Key Wrap out-of-bounds write vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The rust-openssl crate, specifically versions 0.10.24 through 0.10.77, contains a critical vulnerability in the `aes::unwrap_key()` function. This function is intended to perform AES key wrapping, a process used to securely encrypt cryptographic keys. The vulnerability arises from an inverted bounds check on the output buffer size, where the function incorrectly validates the size of the output buffer against the input buffer size. This flaw allows an attacker to potentially write beyond the allocated memory region, leading to a crash or, in more sophisticated scenarios, arbitrary code execution. Exploitation requires that the vulnerable application utilizes AES keywrap and allows the attacker to control the buffer sizes passed to `aes::unwrap_key()`.

## Attack Chain

1. An attacker identifies an application using the vulnerable rust-openssl crate (versions 0.10.24 - 0.10.77) and the `aes::unwrap_key()` function.
2. The attacker crafts a malicious input with specific sizes for the input and output buffers to trigger the vulnerability.
3. The attacker provides a crafted input buffer (`in_`) and a smaller-than-required output buffer (`out`) to the vulnerable `aes::unwrap_key()` function.
4. The incorrect bounds assertion `out.len() + 8 <= in_.len()` passes, as the `out` buffer is intentionally smaller than `in_.len() - 8`.
5. The `aes::unwrap_key()` function proceeds with the AES key wrapping process.
6. During the key unwrapping process, the function attempts to write `in_.len() - 8 - out.len()` bytes beyond the allocated boundary of the `out` buffer.
7. This out-of-bounds write corrupts adjacent memory regions within the application's address space.
8. Depending on the overwritten memory, the attacker can potentially achieve arbitrary code execution or cause a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability can lead to various adverse consequences, including denial of service, information disclosure, or arbitrary code execution. Applications utilizing AES keywrap and accepting attacker-controlled buffer sizes are at the highest risk. The specific impact depends on the application's memory layout and the attacker's ability to control the overwritten memory. Given the widespread use of OpenSSL for cryptographic operations, this vulnerability poses a significant threat to vulnerable applications.

## Recommendation

*   Upgrade the `rust-openssl` crate to version 0.10.78 or later to patch the vulnerability as indicated in [GHSA-8c75-8mhr-p7r9](https://github.com/advisories/GHSA-8c75-8mhr-p7r9).
*   Audit code using `aes::unwrap_key()` to ensure input and output buffer sizes are validated correctly to prevent out-of-bounds writes.
*   Implement runtime memory protection mechanisms to detect and prevent out-of-bounds writes, mitigating the impact of this and similar vulnerabilities.
