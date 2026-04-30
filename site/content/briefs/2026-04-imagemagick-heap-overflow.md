---
title: ImageMagick Heap Buffer Overflow Vulnerability (CVE-2026-33901)
slug: 2026-04-imagemagick-heap-overflow
description: ImageMagick versions before 7.1.2-19 and 6.9.13-44 are vulnerable to a heap buffer overflow in the MVG decoder, potentially leading to an out-of-bounds write when processing a crafted image, which can result in denial of service or arbitrary code execution.
date: "2026-04-13T21:16:25Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - imagemagick
  - heap-buffer-overflow
  - cve-2026-33901
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-33901
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33901
  - https://github.com/ImageMagick/ImageMagick/commit/4c72003e9e54a4ebaa938d239e75f5d285527ebe
  - https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-x9h5-r9v2-vcww
  - https://github.com/dlemstra/Magick.NET/releases/tag/14.12.0
rules:
  - title: ImageMagick MVG Decoder Heap Overflow Attempt
    description: Detects potential attempts to exploit the ImageMagick MVG decoder heap overflow vulnerability (CVE-2026-33901) by monitoring process creation events involving ImageMagick and suspicious arguments.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: ImageMagick Out-of-Bounds Write via MVG
    description: Detects potential ImageMagick out-of-bounds write attempts. This rule identifies instances where ImageMagick processes MVG files and generates errors indicative of memory corruption.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

ImageMagick is a widely used open-source software suite for displaying, converting, and editing raster image files.  CVE-2026-33901 describes a heap buffer overflow vulnerability within the MVG (Magick Vector Graphics) decoder. This flaw exists in ImageMagick versions prior to 7.1.2-19 and 6.9.13-44. An attacker can exploit this vulnerability by crafting a malicious image file. When a vulnerable ImageMagick version processes this crafted image, the MVG decoder attempts to write data beyond the allocated buffer, resulting in an out-of-bounds write. This can lead to application crashes, denial-of-service conditions, or potentially arbitrary code execution on the targeted system.  Organizations utilizing ImageMagick for image processing are vulnerable.

## Attack Chain

1. An attacker crafts a malicious image file containing a specially designed MVG (Magick Vector Graphics) payload.
2. The attacker delivers the crafted image file to a target system, potentially via a web upload form or email attachment.
3. A user or automated process on the target system uses a vulnerable version of ImageMagick to process the image file.
4. The ImageMagick MVG decoder attempts to parse the malicious MVG data within the image.
5. Due to the heap buffer overflow vulnerability (CVE-2026-33901), the decoder writes data beyond the allocated buffer on the heap.
6. This out-of-bounds write corrupts adjacent memory regions.
7. Depending on the overwritten memory, the application might crash, leading to a denial-of-service.
8.  In some scenarios, this memory corruption could potentially be leveraged for arbitrary code execution, allowing the attacker to gain control of the system.

## Impact

Successful exploitation of CVE-2026-33901 can lead to denial of service due to application crashes. In more severe cases, the vulnerability could allow for arbitrary code execution, potentially leading to complete system compromise.  The impact will depend on the privileges of the user account running ImageMagick, but could lead to data loss, system instability, or unauthorized access. Organizations using affected versions of ImageMagick are vulnerable.

## Recommendation

*   Upgrade ImageMagick to version 7.1.2-19 or 6.9.13-44 or later to patch CVE-2026-33901.
*   Monitor web server logs for requests to process image files (e.g., via POST requests) to identify potential exploitation attempts.
*   Implement input validation to restrict the types and sizes of image files that can be uploaded or processed by ImageMagick.
