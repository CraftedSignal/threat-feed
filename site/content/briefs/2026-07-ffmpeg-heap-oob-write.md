---
title: FFmpeg Heap Out-of-Bounds Write Vulnerability (CVE-2026-66036)
slug: 2026-07-ffmpeg-heap-oob-write
description: A heap out-of-bounds write vulnerability exists in FFmpeg through version 8.1.2, specifically within the vf_hqdn3d filter, allowing attackers to corrupt heap memory by providing a crafted video input where frame resolution increases between frames while filtergraph reinitialization is disabled, leading to undersized buffers and a write beyond allocation boundaries.
date: "2026-07-24T20:19:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ffmpeg
  - vulnerability
  - heap-corruption
  - code-execution
  - dos
vendors:
  - FFmpeg
products:
  - FFmpeg (through 8.1.2)
cves:
  - id: CVE-2026-66036
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66036
---

FFmpeg, a widely used multimedia framework, is affected by a critical heap out-of-bounds write vulnerability, identified as CVE-2026-66036, impacting versions up to and including 8.1.2. The flaw resides within the `vf_hqdn3d` filter. An attacker can exploit this by crafting a malicious video file where the frame resolution progressively increases. When this video is processed by a vulnerable FFmpeg instance with the `-reinit_filter 0` option enabled (which disables filtergraph reinitialization), the `vf_hqdn3d.config_input()` function allocates undersized buffers based on the initial, smaller frame. Subsequent processing of larger frames by the `denoise_spatial()` function then attempts to write data beyond these allocated boundaries, resulting in heap memory corruption. This vulnerability can lead to denial of service through application crashes or, potentially, arbitrary code execution, posing a significant risk to systems processing untrusted video content.

## Attack Chain

1. An attacker crafts a malicious video file specifically designed for the `vf_hqdn3d` filter, where the resolution of video frames increases after the initial frame.
2. The malicious video file is delivered to a victim's system, potentially via email attachments, malicious downloads, or by embedding it on a compromised website.
3. A victim's application or service uses a vulnerable version of FFmpeg (through 8.1.2) to process the malicious video.
4. The FFmpeg process executes with the `-reinit_filter 0` option for the `vf_hqdn3d` filter, which prevents dynamic reallocation of buffers for changing frame sizes.
5. During the processing of the initial, smaller frame, the `vf_hqdn3d.config_input()` function allocates memory buffers for line-history based on this initial frame's width.
6. As FFmpeg proceeds to process subsequent frames with higher resolutions, the `denoise_spatial()` function attempts to write data for these larger frames.
7. Due to the undersized, pre-allocated buffers, `denoise_spatial()` writes past the allocated memory boundary, causing a heap out-of-bounds write.
8. This memory corruption leads to an application crash (denial of service) or, with precise exploitation, could allow an attacker to achieve arbitrary code execution on the compromised system.

## Impact

Successful exploitation of CVE-2026-66036 can lead to severe consequences, primarily encompassing denial of service (DoS) due to application crashes. In more advanced scenarios, it could enable arbitrary code execution, allowing an attacker to gain control over the affected system. While specific victim counts or targeted sectors are not detailed in the source, any organization or individual processing untrusted video files with vulnerable FFmpeg versions is at risk. This includes media processing platforms, video hosting services, content delivery networks, and desktop users utilizing FFmpeg-dependent applications. The CVSS v3.1 base score of 8.8 reflects the high severity and potential for critical impact.

## Recommendation

* Patch CVE-2026-66036 by updating FFmpeg to a version beyond 8.1.2 or applying commit `5d7112c` immediately.
* Implement strict input validation and sanitization for all video files processed by FFmpeg, especially from untrusted sources, to mitigate crafted input.
* Monitor FFmpeg process logs for crashes, segmentation faults, or other abnormal termination events, which could indicate attempted exploitation or system compromise.
* Review configurations to minimize usage of the `-reinit_filter 0` option with the `vf_hqdn3d` filter when processing untrusted content.
