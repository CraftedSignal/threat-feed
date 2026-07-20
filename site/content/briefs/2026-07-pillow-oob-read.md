---
title: Pillow Out-of-Bounds Read Vulnerability in McIdas AREA Plugin (CVE-2026-54058)
slug: 2026-07-pillow-oob-read
description: The Pillow library contains an out-of-bounds read vulnerability in its McIdas AREA plugin when processing specially crafted image files opened from a filename, allowing an attacker to manipulate header words to define a 'stride' value smaller than the actual row width, leading to information disclosure through adjacent process memory leakage or denial of service due to a process crash (SIGBUS).
date: "2026-07-20T21:09:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - pillow
  - oob-read
  - image-processing
  - vulnerability
  - information-disclosure
  - denial-of-service
  - python
vendors:
  - Pillow
products:
  - Pillow < 12.3.0
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: reads adjacent process memory (information disclosure)
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: a larger `xsize` reliably crashes the worker with SIGBUS.
    confidence_band: high
cves:
  - id: CVE-2026-54058
    epss: 0.00384
references:
  - https://github.com/advisories/GHSA-62p4-gmf7-7g93
---

A critical out-of-bounds read vulnerability, identified as CVE-2026-54058, affects the Pillow Python imaging library, specifically within its McIdas AREA image plugin. This flaw allows an attacker to craft a malicious McIdas AREA image file that, when opened from a filename by a vulnerable application, can lead to either information disclosure or a denial of service. The vulnerability arises because the library fails to validate an attacker-controlled `stride` value against the actual row width during memory mapping. By setting a `stride` smaller than expected, the library constructs misaligned row pointers, causing subsequent pixel access operations to read beyond the intended buffer into adjacent process memory. This impacts any application that processes user-supplied images by first saving them to disk and then opening them with Pillow versions prior to 12.3.0.

## Attack Chain

1. An attacker crafts a malicious McIdas AREA image file by manipulating specific 32-bit header words, including the image's `xsize`, `ysize`, `offset`, and crucially, setting the `stride` value to be significantly smaller than the calculated natural row width.
2. A vulnerable application processes the malicious image by opening it from a disk path using Pillow's `Image.open()` function.
3. Pillow's `McIdasImagePlugin._open` function reads the attacker-controlled header words from the image file and uses them to determine the image's dimensions and row `stride` without sufficient validation against logical constraints.
4. Pillow's `ImageFile.load` enters its memory-mapping (mmap) branch because the image was opened from a filename and uses a `raw` codec, delegating to the `PyImaging_MapBuffer` function.
5. The `PyImaging_MapBuffer` function in `src/map.c` builds row pointers directly into the memory-mapped file using the maliciously small `stride` value. Although it checks for `stride > 0`, it critically fails to validate that `stride` is at least the natural row width (`xsize * pixelsize`).
6. When the application subsequently attempts to access the image's pixels (e.g., through `Image.tobytes()`, `getpixel`, `convert`, or `save`), the internal raw encoder reads `linesize` bytes per row from these misaligned pointers.
7. This read operation attempts to access memory far beyond the boundaries of the legitimate memory-mapped image buffer, triggering an out-of-bounds read.
8. The out-of-bounds read either results in information disclosure, leaking sensitive data from adjacent process memory, or causes a process crash (SIGBUS), leading to a denial of service for the application.

## Impact

Successful exploitation of CVE-2026-54058 can lead to two primary impacts. Firstly, information disclosure can occur where the decoded "image" contains bytes from the worker process's adjacent heap or mapped memory. This could potentially leak secrets, credentials, or other sensitive user data if the application processes and then serves or stores this compromised image content. Secondly, a denial of service is possible, especially with a larger `xsize`, which reliably crashes the worker process with a SIGBUS signal, rendering the affected application or service unavailable. Any application that opens user-supplied image files from a disk path and uses vulnerable Pillow versions is exposed to these risks.

## Recommendation

* Immediately patch CVE-2026-54058 by upgrading the Pillow library to version 12.3.0 or newer to address the out-of-bounds read vulnerability.
* Implement robust input validation for all user-supplied image files before processing them with Pillow, particularly checking for malformed headers or suspicious `stride` values, even though this should be handled by the patched library.
* Configure system logging to monitor for process crashes (e.g., SIGBUS signals or segmentation faults) in applications that handle image processing, which could indicate a denial of service attempt.
* Enable and monitor network exfiltration logs from image processing servers for sudden increases in outbound data volume or suspicious destinations, which could indicate information disclosure.
