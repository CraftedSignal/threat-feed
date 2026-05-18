---
title: ImageMagick Magick.NET Heap Buffer Overflow Vulnerability (CVE-2026-46520)
slug: 2026-05-imagemagick-heap-overflow
description: A heap buffer over-write vulnerability exists in ImageMagick's IPL decoder when processing multiple images of different dimensions, affecting Magick.NET packages prior to version 14.13.1 and potentially leading to arbitrary code execution.
date: "2026-05-18T20:38:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - heap-overflow
  - image-processing
  - cve
vendors:
  - ImageMagick
products:
  - Magick.NET-Q16-AnyCPU (< 14.13.1)
  - Magick.NET-Q16-HDRI-AnyCPU (< 14.13.1)
  - Magick.NET-Q16-HDRI-OpenMP-arm64 (< 14.13.1)
  - Magick.NET-Q16-HDRI-OpenMP-x64 (< 14.13.1)
  - Magick.NET-Q16-HDRI-arm64 (< 14.13.1)
  - Magick.NET-Q16-HDRI-x64 (< 14.13.1)
  - Magick.NET-Q16-HDRI-x86 (< 14.13.1)
  - Magick.NET-Q16-OpenMP-arm64 (< 14.13.1)
  - Magick.NET-Q16-OpenMP-x64 (< 14.13.1)
  - Magick.NET-Q16-arm64 (< 14.13.1)
  - Magick.NET-Q16-x64 (< 14.13.1)
  - Magick.NET-Q16-x86 (< 14.13.1)
  - Magick.NET-Q8-AnyCPU (< 14.13.1)
  - Magick.NET-Q8-OpenMP-arm64 (< 14.13.1)
  - Magick.NET-Q8-OpenMP-x64 (< 14.13.1)
  - Magick.NET-Q8-arm64 (< 14.13.1)
  - Magick.NET-Q8-x64 (< 14.13.1)
  - Magick.NET-Q8-x86 (< 14.13.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-36wm-hprc-mcf5
rules:
  - title: Detect CVE-2026-46520 Attempt - ImageMagick Processing Multiple Images
    description: Detects potential exploitation attempts of CVE-2026-46520 by monitoring for ImageMagick processes handling multiple image files as arguments.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-46520 Attempt - Suspicious File Conversion by ImageMagick
    description: Detects potential exploitation of CVE-2026-46520 by monitoring for ImageMagick processes converting between different image formats, which could trigger the vulnerability during dimension processing.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A heap buffer over-write vulnerability, tracked as CVE-2026-46520, has been identified in the IPL (Image Processing Library) decoder of ImageMagick's Magick.NET library. This flaw occurs when the software attempts to read multiple images with differing dimensions. Successful exploitation of this vulnerability could allow an attacker to overwrite heap memory, potentially leading to arbitrary code execution within the context of the application using the vulnerable library. This affects a range of Magick.NET packages including Q16, Q8, HDRI variants for AnyCPU, x86, x64 and Arm64 architectures. Users of Magick.NET are advised to upgrade to version 14.13.1 or later to mitigate the risk.

## Attack Chain

1. An attacker crafts a malicious image file or set of image files. These images are specially crafted to have different dimensions and trigger the vulnerability in the IPL decoder.
2. The attacker delivers the malicious image(s) to a system running a vulnerable version of Magick.NET via an upload mechanism, network share, or other means.
3. An application using the vulnerable Magick.NET library attempts to process the attacker-controlled image(s) with the IPL decoder.
4. During the image processing, the IPL decoder incorrectly calculates buffer sizes when handling images with differing dimensions.
5. This leads to a heap buffer over-write, where data is written outside the allocated memory region.
6. The attacker leverages the memory corruption to inject malicious code into the heap.
7. The injected code is executed, granting the attacker control over the application's process.

## Impact

Successful exploitation of CVE-2026-46520 can lead to arbitrary code execution within the application utilizing the vulnerable Magick.NET library. The specific impact depends on the privileges of the application process. This could potentially allow an attacker to gain complete control of the affected system, steal sensitive data, or disrupt services. Since ImageMagick is widely used in image processing applications, web servers, and content management systems, a successful exploit could have widespread consequences.

## Recommendation

*   Upgrade to Magick.NET version 14.13.1 or later to patch CVE-2026-46520.
*   Monitor image processing applications for unexpected behavior or crashes that may indicate exploitation attempts.
*   Consider implementing input validation to restrict the dimensions of images being processed by Magick.NET to mitigate the risk.
