---
title: Libsixel Integer Overflow Vulnerability in img2sixel --crop Option
slug: 2024-01-libsixel-integer-overflow
description: Libsixel versions 1.8.7 and prior contain an integer overflow vulnerability in the `--crop` option of `img2sixel`, leading to an out-of-bounds heap read, potentially causing a crash and information disclosure.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - libsixel
  - integer-overflow
  - heap-read
  - cve-2026-33019
vendors:
  - Libsixel
products:
  - Libsixel
  - img2sixel
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Defense Evasion
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Defense Evasion
cves:
  - id: CVE-2026-33019
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33019
rules:
  - title: Detect img2sixel with Large Crop Values
    description: Detects execution of img2sixel with extremely large --crop values that could indicate exploitation of CVE-2026-33019.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - information_gathering
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect img2sixel Crashes
    description: Detects abnormal termination (crash) of img2sixel process, potentially related to CVE-2026-33019 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - information_gathering
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Libsixel is a SIXEL encoder/decoder implementation derived from kmiya's sixel. Versions 1.8.7 and prior are vulnerable to an integer overflow in the `--crop` option handling of `img2sixel`. This vulnerability allows an attacker to trigger an out-of-bounds heap read by providing a crafted crop argument with positive coordinates up to INT_MAX, which bypasses overflow-safe bounds checking. The vulnerability resides in `sixel_encoder_do_clip()`, where the expression `clip_w + clip_x` overflows when `clip_x` is INT_MAX, leading to the execution of `memmove()` with a source pointer beyond the image buffer. Successful exploitation results in a crash and potential information disclosure. This issue was addressed in version 1.8.7-r1. Defenders should prioritize patching vulnerable systems.

## Attack Chain

1.  Attacker prepares a malicious image file and a crafted command-line argument for `img2sixel` using the `--crop` option. The `clip_x` value in the argument is set to `INT_MAX`.
2.  The attacker executes `img2sixel` with the malicious image and crafted `--crop` argument.
3.  Within `sixel_encoder_do_clip()`, the calculation `clip_w + clip_x` overflows due to `clip_x` being `INT_MAX`, resulting in a large negative value.
4.  The overflowed value bypasses the intended bounds check, which is meant to prevent out-of-bounds access.
5.  The unclamped coordinate is passed to `sixel_frame_clip()` and subsequently to `clip()`.
6.  `clip()` calculates a source pointer that points far beyond the allocated image buffer.
7.  `memmove()` is called with the out-of-bounds source pointer.
8.  The out-of-bounds read from the heap causes a crash, potentially leading to information disclosure.

## Impact

Successful exploitation of this vulnerability allows an attacker to cause a denial-of-service condition due to the application crash. Furthermore, it could lead to potential information disclosure by reading data from unintended memory locations. Given the wide usage of libsixel, a successful exploit could impact numerous systems and applications that rely on this library for image processing.

## Recommendation

*   Upgrade to libsixel version 1.8.7-r1 or later to patch the integer overflow vulnerability (CVE-2026-33019).
*   Monitor systems for the execution of `img2sixel` with extremely large `--crop` values using the provided Sigma rule.
*   Implement input validation and sanitization to prevent potentially malicious arguments being passed to `img2sixel`.
