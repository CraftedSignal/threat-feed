---
title: OpenEXR DWA Lossy Decoder Heap Out-of-Bounds Write Vulnerability
slug: 2026-04-openexr-dwa-oob-write
description: A heap out-of-bounds write vulnerability exists in OpenEXR's DWA lossy decoder due to integer overflow during block pointer calculation, triggered via crafted DWAA files, leading to crashes during DCT execution.
date: "2026-04-09T12:00:00Z"
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

A heap out-of-bounds write vulnerability has been identified in the DWA lossy decoder of OpenEXR versions 3.2.0-3.2.6, 3.3.0-3.3.8, and 3.4.0-3.4.8. The vulnerability stems from an integer overflow in the calculation of per-component block pointers within the `internal_dwa_decoder.h` file. When processing a DWAA compressed image with a large width, the multiplication of `numBlocksX * 64` overflows a signed 32-bit integer, resulting in a wrapped pointer. This wrapped pointer is then used in…
