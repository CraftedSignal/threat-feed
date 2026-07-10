---
title: libcrux-poly1305 Standalone MAC Panic Vulnerability
slug: 2024-01-libcrux-panic
description: An incorrect key length constant in libcrux-poly1305 versions before 0.0.5 causes the `libcrux_poly1305::mac` function to panic due to out-of-bounds memory access when used as a standalone MAC.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rust
  - libcrux-poly1305
  - panic
  - denial-of-service
products:
  - libcrux-poly1305
references:
  - https://github.com/advisories/GHSA-pv9v-5j35-xwcr
rules:
  - title: Detect libcrux-poly1305 Panic in Application Logs
    description: Detects application logs indicating a panic originating from the libcrux-poly1305 library.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - application
      - linux
  - title: Detect libcrux-poly1305 version usage in build files
    description: Detects usage of vulnerable libcrux-poly1305 version in Cargo.toml files
    platform: sigma
    severity: medium
    tactics:
      - vulnerability
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The `libcrux-poly1305` crate, a Rust implementation of the Poly1305 message authentication code, contained a critical vulnerability in versions prior to 0.0.5. An incorrect constant defining the key length caused the `libcrux_poly1305::mac` function to panic due to an out-of-bounds memory access. This vulnerability specifically affected applications using `libcrux-poly1305` as a standalone MAC implementation. The vulnerability was introduced prior to version 0.0.5 and was resolved in version 0.0.5 by correcting the key length constant. Applications relying on the standalone MAC functionality of the vulnerable versions of `libcrux-poly1305` are susceptible to denial-of-service due to the panics. This issue does not affect the use of `libcrux-poly1305` within `libcrux-chacha20poly1305`.

## Attack Chain

1. An application incorporates `libcrux-poly1305` as a dependency for MAC functionality.
2. The application utilizes the `libcrux_poly1305::mac` function to generate a MAC for data integrity.
3. The `libcrux_poly1305::mac` function attempts to access memory based on the incorrect key length constant.
4. Due to the out-of-bounds access, the function triggers a panic.
5. The application crashes due to the unhandled panic.
6. Service availability is interrupted as the application terminates unexpectedly.
7. Repeated attempts to utilize the MAC functionality result in recurring panics and application crashes.

## Impact

The vulnerability leads to a denial-of-service condition for applications that rely on `libcrux-poly1305` as a standalone MAC. Any application using versions prior to 0.0.5 will experience panics when attempting to utilize the `libcrux_poly1305::mac` function. This can result in application crashes and service interruptions, potentially impacting critical functionality. While the advisory does not specify a number of victims, any deployment utilizing the vulnerable library is potentially affected.

## Recommendation

*   Upgrade the `rust/libcrux-poly1305` package to version 0.0.5 or later to remediate the vulnerability, as indicated in the advisory.
*   Monitor application logs for unexpected panics originating from the `libcrux_poly1305::mac` function.
*   Implement automated testing that specifically exercises the standalone MAC functionality to detect any regressions.
