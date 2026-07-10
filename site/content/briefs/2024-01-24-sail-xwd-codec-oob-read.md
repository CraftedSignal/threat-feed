---
title: SAIL Library XWD Codec Out-of-Bounds Read Vulnerability (CVE-2026-40492)
slug: 2024-01-24-sail-xwd-codec-oob-read
description: A memory access vulnerability exists in the SAIL image library's XWD codec due to inconsistent handling of pixel format, potentially leading to crashes or code execution when processing specially crafted image files.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-40492
  - sail
  - xwd
  - image-processing
  - memory-corruption
vendors:
  - SAIL
products:
  - SAIL library
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Defense Evasion
cves:
  - id: CVE-2026-40492
    cvss: 9.8
  - id: CVE-2026-27168
    cvss: 8.8
    epss: 0.00068
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40492
rules:
  - title: Detect Process Loading Vulnerable SAIL Library
    description: Detects processes loading a vulnerable version of the SAIL library based on file hash. This requires endpoint monitoring capable of tracking loaded DLLs/shared objects and their corresponding hashes.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - image_load
      - windows|linux|macos
  - title: Detect Process Opening Potentially Malicious XWD File
    description: Detects processes opening XWD files which could be crafted to exploit CVE-2026-40492. This rule is best paired with other detections to increase fidelity.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - file_event
      - windows|linux|macos
rules_count: 2
---

The SAIL (Simple API for Images Loading) library, a cross-platform tool used for loading and saving images, contains a critical vulnerability (CVE-2026-40492) within its XWD codec. This flaw stems from inconsistent handling of pixel format (`pixmap_depth`) and bit depth (`bits_per_pixel`) during image processing. Specifically, the byte-swap code within the XWD codec incorrectly accesses memory when `pixmap_depth` is set to 8 (indicating 1 byte per pixel) while `bits_per_pixel` is set to 32. This discrepancy causes the code to read and write 4x the allocated buffer size, resulting in an out-of-bounds memory access. This is a distinct vulnerability from CVE-2026-27168. The vulnerability was patched in commit 36aa5c7ec8a2bb35f6fb867a1177a6f141156b02. Successful exploitation could lead to application crashes, denial-of-service, or potentially arbitrary code execution.

## Attack Chain

1. An attacker crafts a malicious XWD image file with `pixmap_depth` set to 8 and `bits_per_pixel` set to 32.
2. A user or application unknowingly processes the malicious XWD image file using the vulnerable SAIL library.
3. The SAIL library's XWD codec attempts to decode the image.
4. During the byte-swapping process, the codec incorrectly calculates the memory access size based on `bits_per_pixel` (32) while using a buffer size based on `pixmap_depth` (8).
5. The byte-swap loop attempts to read and write 4 bytes per pixel, exceeding the allocated buffer size.
6. This results in an out-of-bounds read and write operation, potentially overwriting adjacent memory regions.
7. If the overwritten memory contains critical data or executable code, it could lead to application instability or code execution.
8. The attacker achieves denial of service or potentially gains control of the affected system.

## Impact

Successful exploitation of CVE-2026-40492 can have severe consequences. An attacker could cause applications using the SAIL library to crash, leading to denial of service. In more severe scenarios, the out-of-bounds write could be leveraged to execute arbitrary code, potentially allowing the attacker to gain control of the affected system. The number of potential victims is broad, as the SAIL library is used across multiple platforms and applications that process image files. Sectors that rely heavily on image processing, such as graphic design, medical imaging, and digital photography, are particularly at risk.

## Recommendation

*   Upgrade the SAIL library to a version containing commit 36aa5c7ec8a2bb35f6fb867a1177a6f141156b02 or later to patch CVE-2026-40492.
*   Monitor applications that use the SAIL library for unexpected crashes or memory access violations (requires robust application logging).
*   Consider implementing input validation on image files to ensure that `pixmap_depth` and `bits_per_pixel` values are consistent and within expected ranges, though this is not a complete defense and requires careful implementation.
