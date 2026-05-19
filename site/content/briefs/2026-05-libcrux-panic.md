---
title: 'libcrux-chacha20poly1305: Potential Panic on Overlong Ciphertext Buffer'
slug: 2026-05-libcrux-panic
description: An application that passes an overlong ciphertext buffer to `libcrux_chacha20poly1305::encrypt` or `libcrux_chacha20poly1305::xchacha20_poly1305::encrypt` can experience a panic, leading to a crash if the buffer length is attacker-controlled, affecting libcrux-chacha20poly1305 versions prior to 0.0.8.
date: "2026-05-19T16:21:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - availability
vendors:
  - rust
products:
  - libcrux-chacha20poly1305 (< 0.0.8)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-hc3c-63hc-2r9f
---

A vulnerability exists in `libcrux-chacha20poly1305` versions prior to 0.0.8 where passing a ciphertext buffer with a length greater than `ptxt.len() + TAG_LEN` to the `encrypt` or `xchacha20_poly1305::encrypt` functions triggers a panic. If an attacker can control the length of the ciphertext buffer, this can be exploited to crash the application. The vulnerability was reported on May 19, 2026. The fix ensures that the `encrypt` functions no longer panic, instead writing the ciphertext and tag into the first `ptxt.len() + TAG_LEN` bytes of the provided buffer. This prevents denial-of-service attacks by crashing applications using the vulnerable library.

## Attack Chain

1. The attacker identifies an application using a vulnerable version of `libcrux-chacha20poly1305` (versions < 0.0.8).
2. The attacker locates the code where `libcrux_chacha20poly1305::encrypt` or `libcrux_chacha20poly1305::xchacha20_poly1305::encrypt` are called.
3. The attacker determines how to influence the length of the ciphertext buffer passed to the vulnerable function.
4. The attacker crafts a request or input that provides a ciphertext buffer length greater than `ptxt.len() + TAG_LEN`.
5. The application calls the vulnerable `encrypt` function with the attacker-controlled ciphertext buffer.
6. The `encrypt` function attempts to write beyond the bounds of the intended ciphertext, causing a panic.
7. The Rust runtime unwinds the stack and terminates the affected thread or process.
8. The application crashes, resulting in a denial-of-service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition. An attacker can potentially crash any application utilizing a vulnerable version of the `libcrux-chacha20poly1305` library if they can control the length of the ciphertext buffer. The number of affected applications is currently unknown, but any application using the vulnerable versions of the library is susceptible. This could impact services relying on the availability of applications utilizing this library, causing service interruptions.

## Recommendation

- Upgrade the `libcrux-chacha20poly1305` dependency to version 0.0.8 or later to remediate the vulnerability.
- Monitor application logs for unexpected crashes related to `libcrux-chacha20poly1305` functions.
