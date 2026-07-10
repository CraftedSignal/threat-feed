---
title: SAIL Library PSD Codec Heap Buffer Overflow Vulnerability (CVE-2026-40493)
slug: 2024-01-03-sail-heap-overflow
description: A heap buffer overflow vulnerability exists in the SAIL image loading library's PSD codec due to a mismatch in bytes-per-pixel calculation and pixel buffer allocation in LAB mode, leading to potential code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-40493
  - heap-overflow
  - image-processing
  - sail
vendors:
  - SAIL
products:
  - SAIL
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-40493
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40493
rules:
  - title: Detect SAIL PSD Heap Overflow
    description: Detects potential exploitation attempts of the SAIL PSD heap buffer overflow vulnerability (CVE-2026-40493) by monitoring for abnormal process creation events originating from image processing applications utilizing the SAIL library.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect SAIL PSD Library Loading
    description: Detects the loading of the SAIL PSD library in memory, potentially indicating the presence of vulnerable code.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - image_load
      - windows
rules_count: 2
---

SAIL (Simple API for Images Loading) is a cross-platform library used for loading and saving images, supporting features like animation, metadata handling, and ICC profiles. A critical vulnerability, CVE-2026-40493, has been identified within the PSD codec of SAIL. This flaw stems from an inconsistency in how the library calculates bytes per pixel (bpp) compared to the actual memory allocated for pixel data. Specifically, when processing images in LAB mode with `channels=3` and `depth=16`, the computed `bpp` value doesn't align with the memory allocated by the `BPP40_CIE_LAB` format, resulting in a heap buffer overflow during pixel write operations. The vulnerability affects versions prior to commit c930284445ea3ff94451ccd7a57c999eca3bc979, which contains the necessary patch to resolve this issue. Successful exploitation could lead to arbitrary code execution.

## Attack Chain

1.  An attacker crafts a malicious PSD image specifically designed to trigger the vulnerability. This image is created with LAB color mode, 3 channels, and a depth of 16 bits per channel.
2.  The victim application utilizes the SAIL library to load the crafted PSD image. This could be a photo editor, image viewer, or any other software incorporating SAIL for image processing.
3.  The PSD codec within SAIL calculates the `bpp` value based on the `channels` and `depth` header fields. In this specific case, the calculation results in a `bpp` value of 6.
4.  The pixel buffer is allocated based on the resolved pixel format, `BPP40_CIE_LAB`, which allocates only 5 bytes per pixel.
5.  During pixel writing, the code attempts to write 6 bytes of data into a buffer allocated for only 5 bytes, resulting in a one-byte heap buffer overflow. This overflow occurs deterministically on every row of the image.
6.  The heap buffer overflow corrupts adjacent memory regions on the heap.
7.  Depending on the overwritten data, the attacker could potentially gain control of program execution by overwriting function pointers or other critical data structures.
8.  The attacker achieves arbitrary code execution on the victim's machine, leading to system compromise.

## Impact

Successful exploitation of CVE-2026-40493 allows an attacker to achieve arbitrary code execution on a vulnerable system. This could lead to complete system compromise, data exfiltration, or denial-of-service. Applications that rely on the SAIL library to process PSD images are at risk. The vulnerability's high CVSS score (9.8) indicates its critical severity and potential for widespread impact. The number of affected systems depends on the adoption rate of the SAIL library in various software applications across different sectors.

## Recommendation

*   Upgrade to a version of SAIL that includes commit c930284445ea3ff94451ccd7a57c999eca3bc979 or later to patch CVE-2026-40493.
*   Monitor applications that use the SAIL library for unexpected crashes or anomalous behavior, which could indicate exploitation attempts. Enable process creation logging (Sysmon on Windows) to activate the rule detecting abnormal processes spawned by image processing applications.
*   Deploy the Sigma rule `Detect SAIL PSD Heap Overflow` to identify potential exploitation attempts based on process creation events.
