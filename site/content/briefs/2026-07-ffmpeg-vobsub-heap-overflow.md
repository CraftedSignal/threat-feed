---
title: FFmpeg VobSub Heap Buffer Overflow Vulnerability (CVE-2026-64830)
slug: 2026-07-ffmpeg-vobsub-heap-overflow
description: FFmpeg versions 2.1 through 8.1.2 contain a heap buffer overflow vulnerability (CVE-2026-64830) in the VobSub subtitle demuxer, allowing attackers to corrupt adjacent heap memory by supplying a malicious .sub/.idx subtitle file, potentially leading to arbitrary code execution in applications using FFmpeg's VobSub demuxer.
date: "2026-07-22T17:17:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - heap-overflow
  - ffmpeg
  - arbitrary-code-execution
  - media
vendors:
  - FFmpeg
products:
  - FFmpeg 2.1
  - FFmpeg 8.1.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: potentially achieving arbitrary code execution in any application using FFmpeg's VobSub demuxer
    confidence_band: high
cves:
  - id: CVE-2026-64830
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64830
---

A significant heap buffer overflow vulnerability, identified as CVE-2026-64830, has been discovered in FFmpeg versions ranging from 2.1 through 8.1.2. This flaw resides within the VobSub subtitle demuxer component. The vulnerability can be exploited by an attacker who crafts a specially designed `.sub` or `.idx` subtitle file. This malicious file is configured to declare a number of distinct stream IDs that exceeds the fixed-size array boundaries within `libavformat/mpeg.c`. When an application utilizing FFmpeg's VobSub demuxer attempts to process such a file, the `ff_subtitles_queue_insert()` function triggers an unbounded write beyond the `vobsub->q[]` array, leading to heap memory corruption. Successful exploitation could result in arbitrary code execution within the context of the vulnerable application, posing a severe risk to systems processing untrusted media content.

## Attack Chain

1. An attacker creates a malicious VobSub subtitle file (either `.sub` or `.idx` extension).
2. The crafted subtitle file is specifically designed to declare an excessive number of distinct stream IDs beyond expected limits.
3. The attacker delivers the malicious subtitle file to a victim, typically alongside a video file, enticing them to play the media.
4. A media player or application that uses FFmpeg's VobSub demuxer attempts to parse the malicious subtitle file.
5. During the demuxing process, the `ff_subtitles_queue_insert()` function within FFmpeg is invoked to handle the stream IDs.
6. Due to the overly large number of stream IDs in the malicious file, the function attempts to write data beyond the allocated boundary of the `vobsub->q[]` array.
7. This action results in a heap buffer overflow, corrupting adjacent heap memory within the application's process.
8. The attacker leverages this memory corruption to achieve arbitrary code execution, gaining control over the compromised application and potentially the underlying system.

## Impact

The successful exploitation of CVE-2026-64830 leads directly to arbitrary code execution within any application that processes malicious VobSub subtitle files using vulnerable FFmpeg versions. The primary impact is the complete compromise of the affected application, allowing an attacker to execute commands, install malware, or exfiltrate sensitive data in the context of the user running the application. While the number of observed victims or specific sectors targeted is not detailed, this vulnerability broadly affects any system where FFmpeg is used to handle untrusted subtitle files, such as media servers, video editing software, or streaming platforms, making any user of such systems a potential target.

## Recommendation

* Prioritize patching FFmpeg to a version above 8.1.2 or applying relevant security updates to mitigate CVE-2026-64830.
* Educate users to exercise caution when opening or importing subtitle files (`.sub`, `.idx`) from untrusted or unknown sources.
* Implement application whitelisting to restrict the execution of unauthorized code that might be dropped or executed as a result of exploitation.
* Monitor process creation events for media player applications (log source: process_creation) for unusual child processes, especially those related to shell execution or unexpected network connections.
