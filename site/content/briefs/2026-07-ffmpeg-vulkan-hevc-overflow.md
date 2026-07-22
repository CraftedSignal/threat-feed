---
title: FFmpeg Vulkan HEVC Stack Buffer Overflow (CVE-2026-64831)
slug: 2026-07-ffmpeg-vulkan-hevc-overflow
description: A stack buffer overflow vulnerability exists in the Vulkan HEVC hardware decoder within FFmpeg versions 8.0 through 8.1.2, allowing remote attackers to achieve arbitrary code execution by crafting a malicious HEVC/H.265 bitstream with an oversized vps_num_hrd_parameters value that overwrites return addresses and adjacent stack frames in the vk_hevc_end_frame function.
date: "2026-07-22T17:18:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - buffer-overflow
  - ffmpeg
  - media-processing
  - arbitrary-code-execution
vendors:
  - FFmpeg
products:
  - FFmpeg (8.0 through 8.1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: potentially achieving arbitrary code execution
    confidence_band: high
cves:
  - id: CVE-2026-64831
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64831
---

A significant stack buffer overflow vulnerability, identified as CVE-2026-64831, has been discovered in FFmpeg versions 8.0 through 8.1.2. This flaw resides specifically within the Vulkan HEVC (High Efficiency Video Coding) hardware decoder. Remote attackers can exploit this vulnerability by delivering a specially crafted HEVC/H.265 bitstream. The malicious bitstream contains an oversized `vps_num_hrd_parameters` value that exceeds the `HEVC_MAX_SUB_LAYERS` limit, designed to overflow stack-allocated arrays. When processed by the vulnerable `vk_hevc_end_frame` function, this overflow overwrites critical return addresses and adjacent stack frames, ultimately enabling attackers to achieve arbitrary code execution on affected systems. This vulnerability poses a severe risk to any application or system that uses vulnerable FFmpeg versions to process HEVC/H.265 video content.

## Attack Chain

1. **Craft Malicious Bitstream**: The attacker creates a specially crafted HEVC/H.265 bitstream, embedding a malicious `vps_num_hrd_parameters` value that is larger than the `HEVC_MAX_SUB_LAYERS` threshold.
2. **Embed Malicious Data**: The oversized `vps_num_hrd_parameters` value is placed within the crafted HEVC/H.265 bitstream, ensuring it targets stack-allocated arrays.
3. **Delivery**: The attacker delivers the malicious bitstream to a target system. This could occur through various means, such as embedding it in a video file, streaming content, or a media-sharing platform.
4. **Processing by FFmpeg**: The target system, running a vulnerable version of FFmpeg (8.0 through 8.1.2), attempts to process the HEVC/H.265 bitstream using its Vulkan HEVC hardware decoder.
5. **Function Execution**: The `vk_hevc_end_frame` function within FFmpeg is invoked to handle the HEVC frame processing, including the malicious `vps_num_hrd_parameters` value.
6. **Stack Buffer Overflow**: Due to the oversized value, the `vk_hevc_end_frame` function experiences a stack buffer overflow, causing critical data, including return addresses and adjacent stack frames, to be overwritten.
7. **Arbitrary Code Execution**: The overwritten return address is manipulated to point to attacker-controlled code, leading to arbitrary code execution on the target system with the privileges of the FFmpeg process.

## Impact

Successful exploitation of CVE-2026-64831 allows remote attackers to execute arbitrary code on systems utilizing vulnerable FFmpeg versions for HEVC/H.265 video processing. This can lead to full system compromise, data exfiltration, installation of malware, or disruption of services. The vulnerability's impact is broad, affecting any software or service that integrates FFmpeg as a core component for media handling, potentially impacting a wide range of applications from media players to video editing software and streaming platforms. There are no specific victim counts or targeted sectors mentioned, but any environment processing untrusted HEVC/H.265 video is at risk.

## Recommendation

* Patch CVE-2026-64831 by updating all FFmpeg installations to a version beyond 8.1.2 immediately.
* Implement strong input validation and sanitization for all incoming HEVC/H.265 bitstreams where possible, although this may not prevent exploitation for CVE-2026-64831 due to the nature of the vulnerability.
* Monitor system logs for unexpected process crashes, abnormal memory usage, or unusual network connections originating from applications using FFmpeg, which could indicate attempted exploitation.
