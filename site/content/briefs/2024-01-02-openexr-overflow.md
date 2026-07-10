---
title: OpenEXR PIZ Decoder Integer Overflow Leads to OOB Read/Write
slug: 2024-01-02-openexr-overflow
description: A crafted OpenEXR file can trigger out-of-bounds memory access during PIZ decompression due to a signed 32-bit overflow in the `internal_exr_undo_piz()` function, leading to out-of-bounds reads and writes and potentially causing process crashes or memory corruption; affects OpenEXR versions 3.1.0 to 3.2.6, 3.3.0 to 3.3.8, and 3.4.0 to 3.4.8.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openexr
  - memory-corruption
  - out-of-bounds
  - cve-2026-34588
vendors:
  - OpenEXR
products:
  - OpenEXR
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0008
    tactic_name: Defense Evasion
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0008
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify Tools'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-588r-cr5c-w6hf
iocs:
  - type: url
    value: https://github.com/user-attachments/files/26318946/piz_scanline_redzone.zip
ioc_counts:
  url: 1
rules:
  - title: Detect exrcheck tool execution
    description: Detects execution of the exrcheck tool which is used to validate OpenEXR files and was used in the vulnerability analysis.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
  - title: Detect suspicious file size and extension
    description: Detects a possible crafted OpenEXR file with a large size but still has the .exr extension.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    data_sources:
      - file_event
      - linux
  - title: Detect exploitation of OpenEXR vulnerability via unusual process
    description: Detects a possible crafted OpenEXR file being processed by unusual process
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

A signed 32-bit integer overflow vulnerability exists in the PIZ decoder of OpenEXR, specifically within the `internal_exr_undo_piz()` function. This function advances a wavelet pointer using signed 32-bit arithmetic. By crafting a malicious EXR file, attackers can cause the product of `nx`, `ny`, and `wcount` to overflow and wrap around. This leads to the subsequent channel decoding from an incorrect memory address. Given that the wavelet decode path operates in place, this vulnerability results in both out-of-bounds reads and out-of-bounds writes. This issue has been identified in OpenEXR versions 3.1.0 to 3.2.6, 3.3.0 to 3.3.8, and 3.4.0 to 3.4.8. A proof-of-concept exploit exists, and successful exploitation could lead to crashes and memory corruption.

## Attack Chain

1.  The victim opens a specially crafted `.exr` file using an application that utilizes the OpenEXR library.
2.  The application calls `internal_exr_undo_piz()` to decompress the image data.
3.  Within `internal_exr_undo_piz()`, `wavbuf` is set to `decode->scratch_buffer_1`.
4.  For each channel, the function calls `wav_2D_decode (wavbuf + j, ...)`.
5.  `wavbuf` is advanced with `wavbuf += nx * ny * wcount;`, where nx, ny, and wcount are attacker-controlled integers from the crafted EXR file.
6.  The multiplication of `nx`, `ny`, and `wcount` overflows, wrapping the `wavbuf` pointer to an out-of-bounds memory location.
7.  The next channel's wavelet decode runs on the incorrect, out-of-bounds address.
8.  `wdec14_4()` attempts to read and write to the out-of-bounds memory location, leading to memory corruption or a crash.

## Impact

Successful exploitation allows for arbitrary out-of-bounds read/write operations. The impact ranges from simple process crashes to memory corruption, potentially leading to arbitrary code execution. The severity depends on the allocator layout, surrounding memory protections, and the specific application using the vulnerable OpenEXR library. Exploitation may allow an attacker to overwrite program code or data, leading to a loss of confidentiality, integrity, or availability.

## Recommendation

*   Upgrade OpenEXR to a patched version (>= 3.2.7, >= 3.3.9, >= 3.4.9) to remediate the vulnerability.
*   Monitor for the use of the `exrcheck` tool against potentially malicious `.exr` files, especially those originating from untrusted sources.
*   Inspect network traffic for downloads of `.exr` files from untrusted sources.
*   Implement the provided fix recommendations, such as validating the `nx * ny * wcount` calculation and buffer sizes, within the OpenEXR library where feasible.
