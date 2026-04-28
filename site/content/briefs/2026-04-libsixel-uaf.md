---
title: Libsixel Use-After-Free Vulnerability (CVE-2026-33018)
slug: 2026-04-libsixel-uaf
description: A use-after-free vulnerability exists in libsixel versions 1.8.7 and prior when processing animated GIFs due to improper frame buffer management, potentially leading to code execution.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - libsixel
  - use-after-free
  - CVE-2026-33018
  - gif
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-33018
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33018
rules:
  - title: Detect Loading of Vulnerable Libsixel Library
    description: Detects processes loading a vulnerable version of the libsixel library (<= 1.8.7).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - image_load
      - windows
  - title: Detect GIF processing by applications using libsixel
    description: Detects potentially malicious GIF processing by applications that use libsixel, which can be indicative of an exploitation attempt of CVE-2026-33018.
    platform: sigma
    severity: low
    tactics:
      - execution
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Libsixel, a SIXEL encoder/decoder implementation, is vulnerable to a use-after-free vulnerability (CVE-2026-33018) in versions 1.8.7 and prior. The flaw resides in the `load_gif()` function within `fromgif.c`. The vulnerability stems from the reuse of a single `sixel_frame_t` object across all frames of an animated GIF. The `gif_init_frame()` function unconditionally frees and reallocates `frame->pixels` between frames without checking the object's reference count. This can lead to a dangling pointer if an application uses `sixel_helper_load_image_file()` with a multi-frame callback and the documented usage pattern of `sixel_frame_ref()` and `sixel_frame_get_pixels()`, resulting in a heap use-after-free. Exploitation could result in a crash or, potentially, arbitrary code execution. This issue is resolved in version 1.8.7-r1.

## Attack Chain

1. An attacker crafts a malicious animated GIF file.
2. The attacker delivers the malicious GIF to a vulnerable application using `libsixel`. This delivery mechanism could involve various means, such as embedding the image in a document, website, or email.
3. The vulnerable application uses the `sixel_helper_load_image_file()` function to load the crafted GIF.
4. The `load_gif()` function within `fromgif.c` processes the GIF frames.
5. During processing, the `gif_init_frame()` function frees and reallocates the `frame->pixels` buffer for each frame of the animated GIF without properly managing the object's reference count.
6. A callback function, following the documented usage of `sixel_frame_ref()` to retain a frame and `sixel_frame_get_pixels()` to access the pixel data, now holds a dangling pointer to the previously freed memory.
7. When the callback function attempts to access the pixel data via the dangling pointer, a use-after-free condition occurs.
8. This use-after-free can lead to a program crash or, potentially, allow the attacker to execute arbitrary code by manipulating the freed memory.

## Impact

Successful exploitation of this vulnerability could lead to application crashes, denial of service, or potentially arbitrary code execution. The impact depends on the specific application using the vulnerable `libsixel` library. Applications that process user-supplied animated GIFs are particularly at risk. There is no publicly available information about specific victims or sectors targeted by this vulnerability.

## Recommendation

*   Upgrade to libsixel version 1.8.7-r1 or later to patch CVE-2026-33018.
*   Deploy the Sigma rule to detect processes loading the vulnerable libsixel library and processing GIF files to detect exploitation attempts.
*   Monitor web server logs for requests containing potentially malicious GIF files being uploaded to the server to prevent initial access.
