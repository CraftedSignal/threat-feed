---
title: OpenEXR Heap Information Disclosure in PXR24 Decompression (CVE-2026-34543)
slug: 2026-04-openexr-heap-disclosure
description: OpenEXR is vulnerable to a heap information disclosure in PXR24 decompression, where the undo_pxr24_impl function ignores the actual decompressed size, potentially leading to the exposure of uninitialized heap memory when processing crafted EXR files.
date: "2026-04-04T12:00:00Z"
severities:
  - high
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

A heap information disclosure vulnerability exists in OpenEXR's PXR24 decompression functionality, specifically within the `undo_pxr24_impl` function in `internal_pxr24.c` and `exr_uncompress_buffer()` in `compression.c`. This vulnerability, identified as CVE-2026-34543, stems from the decompression function ignoring the actual decompressed size returned by `exr_uncompress_buffer()`. Instead, it relies on the expected size derived from the EXR file's header metadata. The…
