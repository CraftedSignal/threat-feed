---
title: Out-of-Bounds Write Vulnerability in FFmpeg vf_floodfill Filter (CVE-2026-65705)
slug: 2026-07-ffmpeg-floodfill-oob-write
description: A critical out-of-bounds write vulnerability exists in FFmpeg versions 3.4 through 8.1.2 within the vf_floodfill video filter, which attackers can exploit by providing a specially crafted, dynamically sized video stream with filtergraph reinitialization disabled via -reinit_filter 0, leading to heap corruption, a process crash, and potentially remote code execution.
date: "2026-07-23T20:21:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - vulnerability
  - out-of-bounds-write
  - ffmpeg
  - video-processing
vendors:
  - FFmpeg Project
products:
  - FFmpeg versions 3.4 through 8.1.2
cves:
  - id: CVE-2026-65705
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65705
---

FFmpeg versions 3.4 through 8.1.2 are susceptible to a high-severity out-of-bounds write vulnerability, identified as CVE-2026-65705. This flaw resides within the `vf_floodfill` video filter component. Attackers can leverage this by crafting a malicious video stream that features dynamically sized frames. When such a stream is processed by `ffmpeg` with filtergraph reinitialization explicitly disabled (using the `-reinit_filter 0` command-line argument), the `filter_frame()` function attempts to push flood-fill neighbor data beyond the initially allocated memory boundaries. This heap corruption ultimately leads to a process crash, but depending on the heap layout and system hardening measures, it presents a significant risk for remote code execution. This vulnerability affects a wide range of FFmpeg installations, necessitating immediate patching.

## Attack Chain

1. An attacker crafts a malicious video file specifically designed with dynamically sized frames.
2. The attacker prepares the execution environment, ensuring that the `ffmpeg` command will process the malicious video with the `-reinit_filter 0` argument, which disables filtergraph reinitialization.
3. The victim executes the `ffmpeg` command with the attacker-provided video file and arguments.
4. FFmpeg begins processing the video, and the `vf_floodfill` filter allocates a traversal stack based on the dimensions of the initial frames.
5. A subsequent frame, intentionally larger than the initial frames, is processed by the `vf_floodfill` filter.
6. The `filter_frame()` function attempts to write data for flood-fill neighbors beyond the bounds of the original, smaller memory allocation.
7. This out-of-bounds write corrupts the heap memory of the `ffmpeg` process.
8. The heap corruption causes the `ffmpeg` process to crash, potentially allowing for arbitrary code execution depending on the specific memory layout and system mitigations.

## Impact

Successful exploitation of CVE-2026-65705 leads to heap memory corruption within the FFmpeg process, causing it to crash. This results in denial of service for any service or application relying on the vulnerable FFmpeg instance for video processing. Crucially, depending on the specifics of the heap layout and the system's process hardening mechanisms, this vulnerability can be escalated to remote code execution. If exploited, an attacker could gain control over the affected system, leading to data compromise, further network intrusion, or the deployment of additional malware. The broad use of FFmpeg across various applications means the potential impact could span numerous sectors and critical systems.

## Recommendation

* Patch CVE-2026-65705 immediately by updating all FFmpeg installations to a version beyond 8.1.2.
* Implement host-based intrusion detection systems to monitor for unusual `ffmpeg` process crashes or unexpected terminations.
* Configure application whitelisting to prevent the execution of `ffmpeg` with suspicious command-line arguments like `-reinit_filter 0` from untrusted sources.
* Review and update system hardening configurations to include exploit mitigation techniques such as Address Space Layout Randomization (ASLR) and Data Execution Prevention (DEP), which can reduce the likelihood of successful code execution.
