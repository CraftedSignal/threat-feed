---
title: OpenEXR DWA Lossy Decoder Heap Out-of-Bounds Write Vulnerability
slug: 2026-04-openexr-dwa-oob-write
description: A heap out-of-bounds write vulnerability exists in OpenEXR's DWA lossy decoder due to integer overflow during block pointer calculation, triggered via crafted DWAA files, leading to crashes during DCT execution.
date: "2026-04-09T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - openexr
  - heap-overflow
  - dwaa
  - cve-2026-34589
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-34589
    cvss: 5
    epss: 0.00028
references:
  - https://github.com/advisories/GHSA-p8xc-w3q4-h64x
iocs:
  - type: url
    value: https://github.com/user-attachments/files/26318786/dwa_scanline_exrcheck.zip
ioc_counts:
  url: 1
rules:
  - title: Detect exrcheck crash
    description: Detects crashes of the exrcheck tool that are likely related to OpenEXR vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenEXR LossyDctDecoder_execute crash
    description: Detects crashes within the LossyDctDecoder_execute function indicating a potential out-of-bounds write.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A heap out-of-bounds write vulnerability has been identified in the DWA lossy decoder of OpenEXR versions 3.2.0-3.2.6, 3.3.0-3.3.8, and 3.4.0-3.4.8. The vulnerability stems from an integer overflow in the calculation of per-component block pointers within the `internal_dwa_decoder.h` file. When processing a DWAA compressed image with a large width, the multiplication of `numBlocksX * 64` overflows a signed 32-bit integer, resulting in a wrapped pointer. This wrapped pointer is then used in subsequent decoder operations, leading to out-of-bounds memory access during the lossy DCT execution path. This can be triggered using the `exrcheck` tool, impacting systems where OpenEXR is used to process image files.

## Attack Chain

1. An attacker crafts a malicious OpenEXR image file with DWAA compression and a large image width.
2. The victim uses the `exrcheck` tool or an application linked against a vulnerable OpenEXR library to process the image.
3. The `InputFile` or `ScanLineInputFile` class initiates the image decoding process.
4. The `exr_decoding_run` function is called, which in turn calls `exr_uncompress_chunk`.
5. `exr_uncompress_chunk` calls `internal_exr_undo_dwaa` to decompress the DWAA data.
6. `internal_exr_undo_dwaa` invokes `DwaCompressor_uncompress`.
7. Inside `DwaCompressor_uncompress`, `LossyDctDecoder_execute` is called, triggering the integer overflow when calculating `rowBlock` pointers in `internal_dwa_decoder.h`.
8. `LossyDctDecoder_execute` attempts to write data to an out-of-bounds memory location, resulting in a crash (SEGV).

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition due to a write-side crash, as observed in the `LossyDctDecoder_execute` function. The vulnerability affects applications that utilize the OpenEXR library to process DWAA compressed images. While the source doesn't specify the number of victims or targeted sectors, any system processing untrusted OpenEXR images with affected versions is at risk. This could impact image editing software, rendering pipelines, and other applications that rely on OpenEXR.

## Recommendation

*   Upgrade OpenEXR to versions 3.2.7, 3.3.9, or 3.4.9 or later to patch CVE-2026-34589.
*   Deploy the Sigma rule "Detect exrcheck crash" to identify instances where the `exrcheck` tool crashes due to this vulnerability.
*   Monitor systems for abnormal program termination signals (e.g., SEGV) originating from OpenEXR libraries during image processing, as these may indicate exploitation attempts.
*   Block downloads from the URL `https://github.com/user-attachments/files/26318786/dwa_scanline_exrcheck.zip` to prevent users from downloading a known malicious test case.
