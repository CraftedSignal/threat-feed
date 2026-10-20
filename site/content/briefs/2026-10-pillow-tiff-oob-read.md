---
brief_id: brief-2026-10-20-pillow-tiff-oob-read
event_id: brief-2026-10-20-pillow-tiff-oob-read
revision: 1
activity_at: "2026-10-20T23:53:33Z"
title: 'Pillow: TIFF encoder ColorMap plane-size mismatch heap out-of-bounds read'
slug: 2026-10-pillow-tiff-oob-read
description: A heap-based out-of-bounds read vulnerability in the Pillow TIFF encoder occurs when saving images with crafted metadata, potentially leading to application crashes.
date: "2026-10-20T23:53:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified, detection strategy outlined
cpes:
  - cpe:2.3:a:python:pillow:12.3.0:*:*:*:*:*:*:*
tags:
  - image-processing
  - library-vulnerability
  - denial-of-service
vendors:
  - Python Software Foundation
products:
  - Pillow (12.3.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: The vulnerability is triggered by a crafted image processed through the library.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-pchr-8j38-3x4p
iocs:
  - type: hash_sha256
    value: 5f38e0ead90b97949fb0c98c63f9c68d00ba9181db6631ecb8927376dcc75f4d
ioc_counts:
  hash_sha256: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Check application logs for crashes involving PIL.TiffImagePlugin
      owner: SOC
      due: 48h
      evidence: Vulnerability leads to ASAN process termination
  hunt_leads:
    - lead: Identify applications performing TIFF image processing and metadata retention
      technique_id: T1190
      data_needed:
        - Application dependency inventory
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Pillow 12.3.0 is a common dependency for Python image processing
  mitigation_plan:
    - priority: medium
      action: Upgrade Pillow to the latest available version once a fix is provided
      owner: IT Operations
      addresses: Pillow 12.3.0
      evidence: Official GHSA advisory
---

Pillow version 12.3.0 is vulnerable to a heap-based out-of-bounds read during the TIFF encoding process. The flaw is triggered when an application opens a TIFF file containing a specific ColorMap (tag 320) and subsequently attempts to save the image while retaining existing metadata. Pillow's TIFF encoder allocates a buffer based on a fixed stride of 256 SHORT values; however, if the image metadata specifies `BitsPerSample = 16`, the underlying libtiff library expects a significantly larger data volume per plane. This discrepancy causes libtiff to attempt a 131,072-byte read from a 1,536-byte heap-allocated region. While the defect leads to an ASAN-observed out-of-bounds read and process termination, arbitrary memory disclosure or code execution has not been demonstrated.

## Attack Chain

1. Attacker crafts a malicious TIFF file with `BitsPerSample = 16` and a specifically formatted ColorMap containing 768 SHORT entries.
2. The malicious TIFF file is delivered to a target application that uses the Pillow library to process or convert images.
3. The target application invokes `Image.open()` to load the malicious file, successfully parsing the TIFF metadata.
4. The target application performs image processing or transformation operations.
5. The target application invokes the `Image.save()` function with the `format="TIFF"` parameter.
6. Pillow's `ImagingLibTiffSetField` function allocates a buffer for the ColorMap metadata based on the initial input size.
7. The libtiff encoder triggers a `memcpy` operation, attempting to copy data based on the `BitsPerSample` value rather than the allocated buffer size.
8. The process attempts to read memory outside the allocated heap region, resulting in an out-of-bounds read and immediate process termination.

## Impact

Successful exploitation results in the abnormal termination of the host application process, leading to potential denial-of-service for the affected service. The vulnerability requires the application to process and re-save user-supplied image files while retaining metadata.

## Recommendation

- Monitor applications using Pillow for unexpected process crashes, specifically those associated with TIFF image processing tasks.
- Implement strict validation of TIFF metadata, specifically `BitsPerSample` and `ColorMap` tags, before invoking `Image.save()` on untrusted input.
- Perform static analysis of source code to identify instances where user-supplied TIFF metadata is blindly passed to the Pillow save path.
- Ensure that the Pillow library is updated to the latest available version if a patch is released to address the buffer allocation logic.
- Audit logging for `AddressSanitizer` error reports in test or development environments to proactively identify similar boundary violation defects.
