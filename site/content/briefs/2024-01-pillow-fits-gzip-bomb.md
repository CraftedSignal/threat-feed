---
title: Pillow FITS Image GZIP Decompression Bomb Vulnerability
slug: 2024-01-pillow-fits-gzip-bomb
description: Pillow versions 10.3.0 through 12.1.x are vulnerable to a decompression bomb attack via maliciously crafted FITS images, leading to excessive memory consumption and denial of service, resolved in version 12.2.0.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - decompression-bomb
  - denial-of-service
  - pillow
  - fits
vendors:
  - Pillow
products:
  - Pillow
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-whj4-6x5x-4v2j
  - https://pillow.readthedocs.io/en/stable/releasenotes/8.0.0.html#image-open-add-formats-parameter
rules:
  - title: Detect Pillow Process Opening Suspicious Files
    description: Detects processes running Pillow that are opening files with unusual or suspicious extensions.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Excessive Memory Usage by Python Processes
    description: Detects python processes that are consuming an unusually high amount of memory which may indicate a decompression bomb attack.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Pillow, a widely used Python image processing library, is susceptible to a denial-of-service vulnerability when handling specially crafted FITS (Flexible Image Transport System) image files. This flaw, identified as CVE-2026-40192, exists in versions 10.3.0 up to (but not including) 12.2.0. The vulnerability arises from a lack of proper bounds checking during GZIP decompression of FITS image data. An attacker can exploit this by creating a malicious FITS file containing a GZIP-compressed data stream that, when decompressed, expands to an inordinately large size, exhausting available memory resources. This can lead to an out-of-memory (OOM) crash or severe performance degradation, effectively denying service to applications relying on Pillow for image processing.

## Attack Chain

1.  Attacker crafts a malicious FITS image file containing a GZIP-compressed data stream.
2.  The GZIP compressed stream is engineered to expand to an extremely large size when decompressed.
3.  A vulnerable application using Pillow (versions 10.3.0 - 12.1.x) attempts to open and process the malicious FITS file using the `PIL.Image.open()` function.
4.  Pillow's FITS image decoder begins decompressing the GZIP stream without proper size limits.
5.  The decompression process consumes an excessive amount of memory as the data expands.
6.  System memory is exhausted, leading to either an out-of-memory (OOM) condition or significant performance slowdown.
7.  The application using Pillow crashes or becomes unresponsive.
8.  Denial of service is achieved due to resource exhaustion.

## Impact

Successful exploitation of this vulnerability (CVE-2026-40192) results in a denial-of-service condition. Applications using vulnerable versions of Pillow become unresponsive or crash, disrupting normal operations. The impact is particularly significant for systems that automatically process FITS images, such as astronomical data analysis pipelines or medical imaging applications. The number of affected systems depends on the prevalence of vulnerable Pillow versions within these environments.

## Recommendation

*   Upgrade Pillow to version 12.2.0 or later to remediate the vulnerability as detailed in the advisory ([https://github.com/advisories/GHSA-whj4-6x5x-4v2j](https://github.com/advisories/GHSA-whj4-6x5x-4v2j)).
*   If upgrading is not immediately feasible, limit the file types processed by Pillow using the `formats` parameter to `Image.open()`, excluding FITS files as described in the Pillow documentation ([https://pillow.readthedocs.io/en/stable/releasenotes/8.0.0.html#image-open-add-formats-parameter](https://pillow.readthedocs.io/en/stable/releasenotes/8.0.0.html#image-open-add-formats-parameter)).
*   Implement resource monitoring to detect excessive memory consumption by processes using Pillow, and alert on or terminate such processes.
