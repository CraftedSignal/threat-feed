---
title: FFmpeg NVIDIA NVDEC Double-Free Vulnerability (CVE-2026-64832)
slug: 2026-07-ffmpeg-nvdec-double-free
description: FFmpeg versions 4.4 through 8.1.2 are vulnerable to a double-free condition within the NVIDIA NVDEC hardware decoder component (libavcodec/nvdec.c), allowing attackers to trigger memory corruption by providing a specially crafted video file, which occurs when an error path frees memory via `nvdec_fdd_priv_free` due to no decoder surfaces remaining, and a subsequent layer attempts to free the same frame description data, resulting in a double-free of the underlying decoder context in any FFmpeg-based application using NVDEC hardware acceleration.
date: "2026-07-22T18:17:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - memory-corruption
  - ffmpeg
  - nvdec
  - cve
vendors:
  - FFmpeg
  - NVIDIA
products:
  - FFmpeg 4.4
  - FFmpeg 5.x
  - FFmpeg 6.x
  - FFmpeg 7.x
  - FFmpeg 8.0
  - FFmpeg 8.1.0
  - FFmpeg 8.1.1
  - FFmpeg 8.1.2
cves:
  - id: CVE-2026-64832
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64832
---

A significant double-free vulnerability, tracked as CVE-2026-64832, exists in FFmpeg versions 4.4 through 8.1.2, specifically within the NVIDIA NVDEC hardware decoder component (libavcodec/nvdec.c). This flaw allows an attacker to induce memory corruption by providing a specially crafted video file to an FFmpeg-based application that utilizes NVDEC hardware-accelerated decoding. The vulnerability arises when the `ff_nvdec_start_frame_sep_ref` error path is triggered due to a lack of available decoder surfaces. In this scenario, `nvdec_fdd_priv_free` prematurely releases memory associated with the frame description data. Subsequently, the calling layer attempts to free the same memory, leading to a double-free condition of the underlying decoder context. This issue impacts any application integrating affected FFmpeg versions and leveraging NVIDIA NVDEC for video decoding, posing a risk of application crashes, denial of service, or potentially arbitrary code execution depending on memory layout and exploitation techniques.

## Attack Chain

1. An attacker crafts a malicious video file designed to trigger specific error conditions within FFmpeg's NVDEC decoding process.
2. The victim opens or processes the malicious video file using an FFmpeg-based application configured for NVIDIA NVDEC hardware acceleration.
3. During the decoding process, the FFmpeg application reaches a state where no decoder surfaces are available, triggering an error path.
4. The `ff_nvdec_start_frame_sep_ref` error handling routine is invoked within `libavcodec/nvdec.c`.
5. Within this error path, the `nvdec_fdd_priv_free` function is called, releasing the memory allocated for the frame description data.
6. Subsequently, the higher-level FFmpeg calling layer attempts to free the *same* memory region for the frame description data, leading to a double-free vulnerability.
7. The double-free corrupts memory, potentially causing a crash of the FFmpeg-based application, leading to a denial of service.
8. Depending on the memory corruption primitive and system architecture, this could be escalated to arbitrary code execution, allowing the attacker to run malicious code on the victim's system.

## Impact

The successful exploitation of CVE-2026-64832 can lead to severe consequences for users of affected FFmpeg applications. The primary impact is memory corruption, which typically results in application crashes and denial of service. This could disrupt critical video processing workflows or render affected media playback applications unusable. In more sophisticated exploitation scenarios, memory corruption vulnerabilities like double-frees can be chained with other techniques to achieve arbitrary code execution, allowing attackers to compromise the underlying system. This poses a risk to any system processing untrusted video content using vulnerable FFmpeg versions with NVDEC acceleration, potentially leading to data theft, system control, or further network intrusion.

## Recommendation

* Update FFmpeg to a version beyond 8.1.2 immediately to remediate CVE-2026-64832.
* Identify all applications in your environment that utilize FFmpeg for video processing, especially those configured for NVIDIA NVDEC hardware acceleration.
* Consult the changelogs or security advisories for applications dependent on FFmpeg to ensure they have integrated the patched FFmpeg versions to address CVE-2026-64832.
* As a temporary mitigation if immediate patching is not possible, consider disabling NVIDIA NVDEC hardware acceleration in FFmpeg-based applications or restricting the processing of untrusted video files.
