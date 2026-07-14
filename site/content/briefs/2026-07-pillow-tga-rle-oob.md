---
title: Pillow TGA RLE Encoder Out-of-Bounds Read (CVE-2026-59198)
slug: 2026-07-pillow-tga-rle-oob
description: A critical out-of-bounds read vulnerability, CVE-2026-59198, exists in Pillow versions 5.2.0 through 12.2.x, specifically within its TGA RLE encoder, allowing adjacent process heap bytes to be copied into generated TGA files, which can lead to information disclosure.
date: "2026-07-14T20:42:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - out-of-bounds-read
  - python
vendors:
  - Python
products:
  - Pillow (5.2.0 - 12.2.x)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: allowing adjacent process heap bytes to be copied into the generated TGA file.
    confidence_band: med
cves:
  - id: CVE-2026-59198
    cvss: 6.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59198
  - https://github.com/python-pillow/Pillow/commit/eada3cbd7fb9963ee90673fb7b5270124a0d5f4b
  - https://github.com/python-pillow/Pillow/pull/9709
  - https://github.com/python-pillow/Pillow/releases/tag/12.3.0
  - https://github.com/python-pillow/Pillow/security/advisories/GHSA-fj7v-r99m-22gq
---

Pillow, a popular Python imaging library, contains a high-severity out-of-bounds read vulnerability (CVE-2026-59198) affecting versions 5.2.0 up to, but not including, 12.3.0. The flaw resides in the TGA RLE encoder where, during the process of saving a mode 1 image with TGA RLE compression, the encoder reads past its packed row buffer. This action causes adjacent process heap memory contents to be inadvertently copied into the generated TGA file. This vulnerability enables an attacker to potentially disclose sensitive information stored in the application's heap memory by exploiting an application that uses a vulnerable version of Pillow to save images. The issue was identified and a fix has been implemented in Pillow version 12.3.0.

## Attack Chain

1. An attacker identifies a web application or service that processes and saves images using a vulnerable version of the Pillow library (versions 5.2.0 to 12.2.x).
2. The attacker crafts or manipulates an input that triggers the application to save a "mode 1" image utilizing TGA RLE compression.
3. The vulnerable Pillow TGA RLE encoder, when processing the image saving request, attempts to read beyond the designated packed row buffer.
4. Due to the out-of-bounds read, adjacent bytes from the application's process heap memory are erroneously included in the data written to the output TGA file.
5. The application completes the image saving operation, producing a TGA file that contains both the image data and leaked heap memory contents.
6. The attacker retrieves the generated TGA file, either directly if the application provides it, or through other means if the file is stored in an accessible location.
7. The attacker analyzes the retrieved TGA file to extract the leaked heap memory data, which may contain sensitive information such as pointers, credentials, or other application-specific data.

## Impact

Successful exploitation of CVE-2026-59198 primarily leads to information disclosure. An attacker could potentially extract sensitive data from the process heap, which might include authentication tokens, API keys, partial memory layouts, or other confidential information residing in memory. The severity of the impact depends on the nature of the data present in the adjacent heap memory at the time of exploitation. While no specific victim counts or targeted sectors are mentioned, any application using affected Pillow versions to save TGA images is at risk of leaking internal memory contents.

## Recommendation

* Upgrade all instances of the Pillow library to version 12.3.0 or later to patch CVE-2026-59198.
* Review applications that handle image processing, especially those saving TGA format images, to ensure they are using a secure version of the Pillow library.
