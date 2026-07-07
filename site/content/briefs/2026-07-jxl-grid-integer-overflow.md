---
title: JXL-Grid Integer Overflow Leads to Out-of-Bounds Write (CVE-2026-52834)
slug: 2026-07-jxl-grid-integer-overflow
description: A critical vulnerability, CVE-2026-52834, affects the `jxl-grid` library on 32-bit platforms, where an integer overflow during length calculation while decoding a crafted JPEG XL image can lead to out-of-bounds writes, potentially resulting in arbitrary code execution.
date: "2026-07-03T11:13:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - jpeg-xl
  - integer-overflow
  - rce
  - library
  - 32-bit
  - memory-corruption
vendors:
  - JXL Community
products:
  - jxl-grid (<= 0.6.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: On 32-bit platforms, decoding a crafted image may lead to out-of-bounds writes due to integer overflow in length calculation. ... This could allow arbitrary code execution.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-5pmv-rx8r-wmv5
---

A significant security vulnerability, identified as CVE-2026-52834, has been discovered in the `jxl-grid` Rust library, specifically impacting applications running on 32-bit platforms. This flaw stems from an integer overflow during length calculations when decoding specially crafted JPEG XL images. Attackers can exploit this by engineering images with dimensions that exceed `usize` limits on 32-bit systems, either by specifying extremely large actual frame dimensions (e.g., 65536 x 65536) or by combining a huge canvas with a small cropped frame. The resulting integer overflow causes the library to allocate insufficient memory, leading to out-of-bounds writes during image processing. Successful exploitation of this vulnerability could allow an attacker to achieve arbitrary code execution within the context of the vulnerable application, posing a severe risk to data integrity and system control. The vulnerability affects `jxl-grid` versions up to and including 0.6.1.

## Attack Chain

1.  An attacker crafts a malicious JPEG XL image file designed to trigger an integer overflow on 32-bit systems when processed by the `jxl-grid` library.
2.  The crafted image contains specific dimensions (e.g., `65536 x 65536` pixels) or canvas/region parameters that cause the product of width and height to exceed the maximum value representable by `usize` on a 32-bit platform.
3.  A victim's application, compiled for and running on a 32-bit operating system, attempts to process or decode the attacker-controlled JPEG XL image using the vulnerable `jxl-grid` library (version <= 0.6.1).
4.  During internal memory allocation calculations, specifically within functions like `AlignedGrid::with_alloc_tracker` or related rendering paths in `crates/jxl-render/src/blend.rs`, the integer overflow occurs due to the maliciously large dimension values.
5.  This integer overflow causes the `jxl-grid` library to allocate a significantly smaller memory buffer than required for the actual image data, creating a heap buffer underflow condition.
6.  Subsequent operations by the `jxl-grid` library, such as attempting to write decoded pixel data into `subgrids` (e.g., via `as_subgrid_mut().get_mut()`), access memory locations beyond the boundaries of the undersized buffer.
7.  These out-of-bounds writes allow the attacker to corrupt adjacent memory regions with attacker-controlled data that is embedded within the crafted image.
8.  Through carefully manipulated memory corruption, the attacker achieves arbitrary code execution within the context of the vulnerable application that was processing the malicious JPEG XL image.

## Impact

On 32-bit platforms, this vulnerability can cause applications using the `jxl-grid` library to crash or become compromised due to out-of-bounds writes during the decoding of specially crafted JPEG XL images. The most severe impact is the potential for arbitrary code execution, allowing attackers to run malicious code within the context of the affected application. This could lead to data theft, system control, or further network compromise. While no specific victim counts or targeted sectors are provided, any organization or individual processing untrusted JPEG XL images on 32-bit systems using the affected library is at risk.

## Recommendation

*   Patch CVE-2026-52834 immediately by updating the `jxl-grid` library to a version greater than 0.6.1.
