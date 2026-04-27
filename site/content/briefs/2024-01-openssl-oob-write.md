---
title: rust-openssl AES Key Wrap Out-of-Bounds Write Vulnerability
slug: 2024-01-openssl-oob-write
description: The rust-openssl package is vulnerable to an out-of-bounds write due to an incorrect bounds assertion in the `aes::unwrap_key()` function, potentially leading to arbitrary code execution if attacker-controlled buffer sizes are permitted.
date: "2024-01-29T12:00:00Z"
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

The rust-openssl crate, specifically versions 0.10.24 through 0.10.77, contains a critical vulnerability in the `aes::unwrap_key()` function. This function is intended to perform AES key wrapping, a process used to securely encrypt cryptographic keys. The vulnerability arises from an inverted bounds check on the output buffer size, where the function incorrectly validates the size of the output buffer against the input buffer size. This flaw allows an attacker to potentially write beyond the…
