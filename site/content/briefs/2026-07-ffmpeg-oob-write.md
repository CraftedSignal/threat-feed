---
title: Critical Out-of-Bounds Write Vulnerability in FFmpeg (CVE-2026-65706)
slug: 2026-07-ffmpeg-oob-write
description: A critical out-of-bounds write vulnerability (CVE-2026-65706) exists in FFmpeg versions 3.0 through 8.1.2 within the vf_swaprect video filter, allowing attackers to corrupt heap memory and achieve potential remote code execution by providing a specially crafted NV12 video frame with odd width dimensions.
date: "2026-07-23T20:22:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - RCE
  - out-of-bounds-write
  - video-processing
  - FFmpeg
vendors:
  - FFmpeg
products:
  - FFmpeg versions 3.0 through 8.1.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: FFmpeg versions 3.0 through 8.1.2 contain an out-of-bounds write vulnerability ... that allows attackers to corrupt heap memory ... with potential for code execution.
    confidence_band: high
cves:
  - id: CVE-2026-65706
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65706
---

A critical out-of-bounds write vulnerability, identified as CVE-2026-65706, affects FFmpeg versions 3.0 through 8.1.2. This flaw resides within the `vf_swaprect` video filter, specifically impacting how it handles NV12 video frames with odd width dimensions. Threat actors can exploit this by supplying a specially crafted video frame, causing the `filter_frame()` function to perform an 18-byte `memcpy` operation into a 17-byte heap allocation. This discrepancy, stemming from incorrect temporary buffer sizing for interleaved chroma planes, leads to heap corruption and a subsequent process crash. Successful exploitation can enable remote code execution, granting attackers unauthorized control over the affected system. This vulnerability poses a significant risk to applications and services utilizing vulnerable FFmpeg versions for video processing, as it can be triggered by merely processing a malicious video file or stream.

## Attack Chain

1. An attacker crafts a malicious NV12 video frame designed with odd width dimensions.
2. The crafted video frame includes specially structured data intended to trigger an out-of-bounds write condition.
3. The victim's system, running a vulnerable FFmpeg version (3.0 through 8.1.2), processes the attacker-supplied malicious NV12 video frame.
4. The FFmpeg `vf_swaprect` video filter's `filter_frame()` function is invoked to process the crafted frame.
5. During the processing of the two-byte-per-sample interleaved chroma plane, the `filter_frame()` function reuses a temporary row buffer sized for plane 0's single-byte pixel step.
6. This incorrect sizing causes an 18-byte `memcpy` operation to occur into a 17-byte heap allocation, triggering an out-of-bounds write.
7. The out-of-bounds write corrupts heap memory, leading to a process crash of the FFmpeg application or service.
8. With sophisticated crafting, this heap corruption can be exploited to achieve arbitrary code execution, allowing the attacker to gain control over the affected FFmpeg process and potentially the underlying system.

## Impact

Successful exploitation of CVE-2026-65706 results in heap memory corruption, leading to denial of service through application crashes. The vulnerability carries a high CVSS v3.1 base score of 7.8, indicating significant severity. The primary risk is the potential for remote code execution, which would allow an attacker to execute arbitrary commands and take complete control of the system running the vulnerable FFmpeg software. This could lead to data exfiltration, further network compromise, or the installation of additional malicious software. Any application or service that uses FFmpeg for video processing, including media players, video conferencing tools, transcoding services, and content management systems, is at risk. The number of potential victims is vast due to the widespread use of FFmpeg across various industries.

## Recommendation

* Patch CVE-2026-65706 immediately by upgrading FFmpeg to a version beyond 8.1.2 that addresses this vulnerability.
* Monitor systems for unexpected process crashes related to FFmpeg or media processing applications to detect potential exploitation attempts of CVE-2026-65706.
