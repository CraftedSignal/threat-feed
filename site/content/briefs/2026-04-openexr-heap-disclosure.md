---
title: OpenEXR Heap Information Disclosure in PXR24 Decompression (CVE-2026-34543)
slug: 2026-04-openexr-heap-disclosure
description: OpenEXR is vulnerable to a heap information disclosure in PXR24 decompression, where the undo_pxr24_impl function ignores the actual decompressed size, potentially leading to the exposure of uninitialized heap memory when processing crafted EXR files.
date: "2026-04-04T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - openexr
  - heap-disclosure
  - cve-2026-34543
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2026-34543
    epss: 0.0004
references:
  - https://github.com/advisories/GHSA-vc68-257w-m432
iocs:
  - type: url
    value: https://github.com/user-attachments/files/26002361/poc.zip
    context: Proof-of-concept exploit code
  - type: url
    value: https://github.com/AcademySoftwareFoundation/openexr.git
ioc_counts:
  url: 2
rules:
  - title: Detect OpenEXR PXR24 Decompression with Short Output
    description: Detects processes potentially exploiting CVE-2026-34543 by monitoring for decompression calls that may result in short output when handling EXR files. This rule focuses on identifying processes that use the vulnerable OpenEXR library and might be processing crafted EXR files.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenEXR PXR24 Decompression with High Memory Usage
    description: Detects processes that exhibit abnormally high memory usage while decompressing PXR24 EXR files, which might indicate an attempt to exploit CVE-2026-34543. This rule identifies processes using decompression functions associated with OpenEXR and monitors their memory allocation patterns.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A heap information disclosure vulnerability exists in OpenEXR's PXR24 decompression functionality, specifically within the `undo_pxr24_impl` function in `internal_pxr24.c` and `exr_uncompress_buffer()` in `compression.c`. This vulnerability, identified as CVE-2026-34543, stems from the decompression function ignoring the actual decompressed size returned by `exr_uncompress_buffer()`. Instead, it relies on the expected size derived from the EXR file's header metadata. The `exr_uncompress_buffer()` also treats `LIBDEFLATE_SHORT_OUTPUT` as a successful result. An attacker can exploit this by crafting a malicious PXR24 EXR file containing a truncated zlib stream. This leads to the decoder reading uninitialized heap memory and incorporating it into the output pixel data, potentially exposing sensitive information. The vulnerability affects OpenEXR versions 3.2.0 through 3.2.6, 3.3.0 through 3.3.8, and 3.4.0 through 3.4.7.

## Attack Chain

1. The attacker crafts a malicious PXR24 EXR file with a truncated zlib stream.
2. The victim application uses OpenEXR to open and process the malicious EXR file.
3. The `undo_pxr24_impl` function is called to decompress the PXR24 compressed data.
4. The `exr_uncompress_buffer` function decompresses the truncated zlib stream, returning `LIBDEFLATE_SHORT_OUTPUT`, which is treated as a success.
5. `undo_pxr24_impl` ignores the actual decompressed size (`outSize`) and reads from the scratch buffer based on the expected size (`uncompressed_size`) from the header.
6. The byte-plane reconstruction loop reads past the valid decompressed data into uninitialized heap memory within the scratch buffer.
7. The uninitialized heap memory is incorporated into the output pixel data.
8. The victim application processes the pixel data, potentially leaking sensitive information from the heap.

## Impact

Successful exploitation of this vulnerability results in a heap information disclosure. Sensitive information from the heap memory may be leaked through the decoded pixel data. The vulnerability is triggered simply by opening a malicious EXR file, requiring no user interaction beyond processing the image. The vulnerable versions of OpenEXR are commonly used in image processing applications, 3D rendering software, and other tools that handle EXR image files. This can lead to data breaches, exposure of confidential information, and potential further compromise of affected systems.

## Recommendation

*   Apply the patch or upgrade to a fixed version of OpenEXR to address CVE-2026-34543.
*   Monitor network traffic and file system activity for attempts to deliver or access suspicious EXR files from untrusted sources.
*   Implement input validation and sanitization measures to prevent the processing of potentially malicious EXR files (reference CVE-2026-34543).
*   Deploy the Sigma rule provided below to detect processes decompressing EXR files that may exhibit anomalous behavior indicative of exploitation.
