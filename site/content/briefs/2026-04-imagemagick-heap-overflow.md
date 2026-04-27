---
title: ImageMagick Heap Buffer Overflow Vulnerability (CVE-2026-33901)
slug: 2026-04-imagemagick-heap-overflow
description: ImageMagick versions before 7.1.2-19 and 6.9.13-44 are vulnerable to a heap buffer overflow in the MVG decoder, potentially leading to an out-of-bounds write when processing a crafted image, which can result in denial of service or arbitrary code execution.
date: "2026-04-13T21:16:25Z"
severities:
  - high
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

ImageMagick is a widely used open-source software suite for displaying, converting, and editing raster image files.  CVE-2026-33901 describes a heap buffer overflow vulnerability within the MVG (Magick Vector Graphics) decoder. This flaw exists in ImageMagick versions prior to 7.1.2-19 and 6.9.13-44. An attacker can exploit this vulnerability by crafting a malicious image file. When a vulnerable ImageMagick version processes this crafted image, the MVG decoder attempts to write data beyond the…
