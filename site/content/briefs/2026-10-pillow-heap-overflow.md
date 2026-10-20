---
brief_id: brief-2026-10-20-pillow-heap-overflow
event_id: brief-2026-10-20-pillow-heap-overflow
revision: 1
activity_at: "2026-10-20T23:53:08Z"
title: 'Pillow: Heap buffer overflow in ImagingJpegDecode'
slug: 2026-10-pillow-heap-overflow
description: A heap-based buffer overflow in Pillow’s ImagingJpegDecode function occurs when processing lossless (SOF3) JPEG files, leading to out-of-bounds memory writes during scanline decompression.
date: "2026-10-20T23:53:08Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - image-processing
  - memory-corruption
  - heap-overflow
vendors:
  - python-pillow
products:
  - Pillow
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: The heap buffer overflow can lead to arbitrary memory writes during the image decompression process.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-8g5g-8vmr-9782
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory applications using Pillow and prepare for deployment of patched versions.
      owner: IT Operations
      due: 48h
  hunt_leads:
    - lead: Monitor application logs for frequent OSErrors in Pillow image processing pipelines.
      technique_id: T1059
      data_needed:
        - Application exception logs
      priority: medium
      confidence: medium
      disposition: hunt_now
  mitigation_plan:
    - priority: immediate
      action: Upgrade Pillow to the latest version once the fix is released.
      owner: IT Operations
      addresses: Pillow
---

Pillow contains a heap-based buffer overflow vulnerability within the `ImagingJpegDecode` function. The issue arises when the library processes lossless (SOF3) JPEG images while performing downscaling, such as when calling `Image.thumbnail()` or `JpegImageFile.draft()`. When these methods request a scaled output, Pillow shrinks the internal decode buffer to match the expected scaled dimensions. However, the underlying libjpeg-turbo implementation ignores the scaling request for lossless (SOF3) streams and writes full-width scanlines into the undersized buffer.

An attacker can exploit this by providing a maliciously crafted, standards-compliant 8-bit grayscale lossless JPEG. The buffer overflow occurs because there is no geometry validation comparing the libjpeg output dimensions against the allocated `state->buffer`. Depending on the image dimensions and requested scaling factors, this can result in writing attacker-controlled pixel data past the end of the heap-allocated buffer. While the library ultimately throws an `OSError` due to geometry mismatches, the memory corruption occurs during the decompression process.

## Attack Chain

1. Attacker crafts a standards-compliant 8-bit grayscale lossless (SOF3) JPEG image file.
2. Attacker hosts or delivers the file to a target system utilizing a vulnerable version of Pillow.
3. The victim application calls `Image.open()` on the malicious file, which is parsed successfully by Pillow's SOF parser.
4. The application calls `Image.thumbnail()` or `JpegImageFile.draft()` on the image object, triggering a scaling request (e.g., scale factor s >= 2).
5. Pillow computes expected scaled dimensions and allocates a `state->buffer` using `calloc` based on the reduced size.
6. The `ImagingJpegDecode` function calls `jpeg_start_decompress` and proceeds to `jpeg_read_scanlines` without validating the actual JPEG output dimensions.
7. libjpeg-turbo writes the full-width pixel scanlines into the undersized buffer, causing an out-of-bounds heap write of `(W - ceil(W/s)) x components` bytes.
8. The overflow corrupts heap memory with attacker-controlled pixel values.

## Impact

Successful exploitation allows for memory corruption on systems using Pillow to process user-supplied images. This can lead to application crashes or potentially arbitrary code execution depending on the heap layout and the ability to influence memory state through crafted pixel data. This vulnerability affects any system or service that automatically generates thumbnails or processes image uploads using Pillow with standard library defaults.

## Recommendation

1. Identify and inventory all applications within the environment that utilize the Pillow library for image processing.
2. Implement strict input validation or sanitization for JPEG files to detect or reject lossless (SOF3) images if the functionality is not explicitly required.
3. Monitor internal application logs for `OSError` exceptions originating from `PIL.JpegImagePlugin` or `libImaging` during image processing, as these may indicate attempted exploitation.
4. Apply patches provided by the Pillow project as soon as they become available for the affected versions.
