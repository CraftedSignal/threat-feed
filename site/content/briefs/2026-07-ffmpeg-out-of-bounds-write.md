---
title: FFmpeg TDSC Video Decoder Out-of-Bounds Write Vulnerability
slug: 2026-07-ffmpeg-out-of-bounds-write
description: An out-of-bounds write vulnerability (CVE-2026-65703) exists in the TDSC video decoder within FFmpeg versions 2.7 through 8.1.2, allowing remote attackers to cause heap corruption and potential code execution by supplying a specially crafted AVI file with changing frame dimensions across TDSF frames.
date: "2026-07-23T20:20:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - media-processing
  - code-execution
vendors:
  - FFmpeg
products:
  - FFmpeg 2.7
  - FFmpeg 8.1.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: remote attackers to cause heap corruption by supplying a crafted AVI file... potential code execution.
    confidence_band: high
cves:
  - id: CVE-2026-65703
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65703
---

FFmpeg versions 2.7 through 8.1.2 are susceptible to an out-of-bounds write vulnerability (CVE-2026-65703) in its TDSC video decoder. This critical flaw allows remote attackers to trigger heap corruption and potentially achieve arbitrary code execution. The vulnerability is exploited by supplying a specially crafted Audio Video Interleave (AVI) file, which maliciously alters frame dimensions across TDSF (TrueMotion Video Codec) frames. This manipulation leads to incorrect memory handling when `tdsc_parse_tdsf()` attempts to reuse reference frames without proper de-referencing, causing `tdsc_blit()` and `tdsc_yuv2rgb()` functions to write attacker-controlled pixel data beyond the allocated buffer boundaries. The impact ranges from application crashes to the possibility of full system compromise if code execution is achieved. This affects any system or application that uses vulnerable FFmpeg libraries to process media files.

## Attack Chain

1. An attacker crafts a malicious AVI file that utilizes the TDSF (TrueMotion Video Codec) format.
2. The crafted AVI file is engineered to change frame dimensions between successive TDSF frames.
3. A user or automated system processes the malicious AVI file using a vulnerable FFmpeg version (2.7 through 8.1.2).
4. FFmpeg's `tdsc_parse_tdsf()` function processes the malformed frame dimension changes.
5. During this processing, `tdsc_parse_tdsf()` fails to properly unreference an existing reference frame before calling `av_frame_get_buffer()` for a new frame of a different size.
6. This misallocation results in `tdsc_blit()` and `tdsc_yuv2rgb()` functions attempting to write pixel data from the new frame into an undersized, previously allocated reference frame buffer.
7. The write operation extends beyond the boundaries of the allocated memory, causing an out-of-bounds write and heap corruption within the FFmpeg process.
8. This heap corruption leads to an application crash and, under specific conditions, can be leveraged by the attacker to achieve arbitrary code execution on the system where FFmpeg is running.

## Impact

Successful exploitation of CVE-2026-65703 leads to heap corruption within the FFmpeg process, primarily resulting in a denial-of-service condition due to application crashes. The vulnerability also carries the potential for arbitrary code execution, enabling remote attackers to fully compromise affected systems. While specific victim numbers or targeted sectors are not provided, any system processing untrusted media files via vulnerable FFmpeg libraries is at risk. This includes media servers, content management systems, video editing software, and potentially web applications that handle user-uploaded video content.

## Recommendation

* Patch CVE-2026-65703 by upgrading FFmpeg to version 8.1.3 or later on all affected systems immediately.
* Implement robust input validation and sanitization for all user-supplied media files before processing them with FFmpeg.
* Monitor application logs for unexpected crashes or error messages related to media processing involving `ffmpeg` or `libavcodec` components.
