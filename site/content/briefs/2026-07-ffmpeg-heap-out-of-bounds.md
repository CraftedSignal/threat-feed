---
title: FFmpeg Heap Out-of-Bounds Write Vulnerability (CVE-2026-66041)
slug: 2026-07-ffmpeg-heap-out-of-bounds
description: A heap out-of-bounds write vulnerability exists in the vf_quirc filter of FFmpeg versions 7.0 through 8.1.2, allowing an attacker to corrupt heap memory and potentially achieve arbitrary code execution by supplying a crafted PGS/SUP subtitle file with mismatched frame dimensions.
date: "2026-07-24T20:21:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ffmpeg
  - vulnerability
  - heap-overflow
  - rce
vendors:
  - FFmpeg
products:
  - FFmpeg 7.0
  - FFmpeg 8.1.2
cves:
  - id: CVE-2026-66041
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66041
---

A critical heap out-of-bounds write vulnerability, identified as CVE-2026-66041, has been discovered in FFmpeg versions 7.0 through 8.1.2. This flaw resides within the `vf_quirc` filter, which is utilized for processing subtitle files. An attacker can exploit this vulnerability by providing a specially crafted PGS/SUP subtitle file to a system running a vulnerable FFmpeg version. The malicious subtitle file is engineered to contain a second presentation entry with larger dimensions than its preceding first presentation. When FFmpeg attempts to process this malformed file, the `av_image_copy_plane()` function is triggered, leading to a write operation that exceeds the allocated buffer size for the `libquirc` grayscale image. This results in heap memory corruption, which can cause a denial of service (process crash) or, more critically, arbitrary code execution, enabling attackers to compromise the affected system. The vulnerability was addressed in FFmpeg commit 4da9812.

## Attack Chain

1. An attacker crafts a malicious PGS/SUP subtitle file specifically designed to exploit the CVE-2026-66041 vulnerability.
2. The crafted subtitle file includes at least two presentation entries, where the second entry specifies image dimensions that are larger than those of the first entry.
3. The attacker delivers this malicious subtitle file to a victim's system, potentially via a malicious website, email attachment, or by embedding it within other media content.
4. A vulnerable application utilizing FFmpeg (versions 7.0 through 8.1.2) attempts to process the received PGS/SUP subtitle file using its `vf_quirc` filter component.
5. During the processing of the second presentation frame, the `av_image_copy_plane()` function is invoked to copy image data.
6. Due to the manipulated mismatched dimensions, `av_image_copy_plane()` performs an out-of-bounds write, copying data beyond the allocated `libquirc` grayscale image buffer.
7. This out-of-bounds write corrupts the heap memory of the FFmpeg process that is handling the subtitle file.
8. The heap corruption ultimately leads to a process crash (denial of service) or can be further leveraged by the attacker to achieve arbitrary code execution within the context of the vulnerable application.

## Impact

Successful exploitation of CVE-2026-66041 can lead to severe consequences for systems utilizing vulnerable FFmpeg versions. The primary observed damage involves a denial of service, where affected applications processing the malicious subtitle file crash unexpectedly. More critically, the heap corruption can be leveraged to achieve arbitrary code execution. This allows attackers to gain unauthorized control over the compromised system, potentially enabling them to install additional malware, exfiltrate sensitive data, or disrupt operations. The vulnerability has a CVSS v3.1 base score of 8.8, indicating a high-severity threat. Any software, streaming service, or media processing tool that uses FFmpeg 7.0 through 8.1.2 and processes untrusted PGS/SUP subtitle files is at risk.

## Recommendation

* Immediately apply patches for CVE-2026-66041 by upgrading FFmpeg installations to a version beyond 8.1.2 or incorporating the fix from commit 4da9812.
* Implement robust input validation and sanitization for all incoming PGS/SUP subtitle files to prevent the processing of malicious or malformed data that could trigger CVE-2026-66041.
* Monitor systems that process untrusted media content for unexpected application crashes or unusual process behavior originating from FFmpeg.
