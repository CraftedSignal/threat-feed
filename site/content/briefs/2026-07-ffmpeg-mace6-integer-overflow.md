---
title: FFmpeg MACE6 Audio Decoder Integer Overflow Vulnerability
slug: 2026-07-ffmpeg-mace6-integer-overflow
description: A signed integer overflow vulnerability, CVE-2026-66039, exists in the MACE6 audio decoder of FFmpeg versions through 8.1.2, allowing attackers to corrupt heap memory and achieve code execution by supplying a crafted CAF file with malicious bytes_per_packet and frames_per_packet values.
date: "2026-07-24T20:20:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - integer-overflow
  - code-execution
  - ffmpeg
  - multimedia
vendors:
  - FFmpeg
products:
  - FFmpeg 8.1.2
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This vulnerability could enable code execution.
    confidence_band: high
cves:
  - id: CVE-2026-66039
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66039
---

A critical signed integer overflow vulnerability, identified as CVE-2026-66039, exists within the MACE6 audio decoder component of FFmpeg, affecting versions up to and including 8.1.2. This flaw enables an attacker to corrupt heap memory and potentially achieve arbitrary code execution. The vulnerability is triggered when a specially crafted Common Audio Format (CAF) file is processed by FFmpeg. This malicious file contains oversized `bytes_per_packet` and `frames_per_packet` values embedded within its `desc` chunk. When FFmpeg attempts to calculate output sample counts using these values in the `mace_decode_frame()` function, a signed integer overflow occurs. This leads to an undersized buffer being allocated on the heap, subsequently resulting in a heap out-of-bounds write. Adversaries can leverage this memory corruption to execute arbitrary code. Given FFmpeg's widespread integration into various multimedia applications across Windows, Linux, and macOS, this vulnerability poses a significant risk for remote code execution if untrusted CAF files are processed.

## Attack Chain

1. An attacker crafts a malicious Common Audio Format (CAF) file.
2. The crafted CAF file contains excessively large `bytes_per_packet` and `frames_per_packet` values embedded within its `desc` chunk.
3. The attacker delivers the malicious CAF file to a victim system or application that uses FFmpeg.
4. The victim's application, running an affected FFmpeg version (through 8.1.2), attempts to decode the CAF file using the MACE6 audio decoder.
5. During the `mace_decode_frame()` function's execution, FFmpeg computes the output sample count using the attacker-controlled `bytes_per_packet` and `frames_per_packet` values.
6. This computation results in a signed integer overflow due to the oversized input values.
7. The integer overflow leads to the allocation of an undersized buffer on the heap for the decoded audio data.
8. Subsequent write operations by FFmpeg into this undersized buffer cause a heap out-of-bounds write, corrupting adjacent heap memory and potentially enabling arbitrary code execution.

## Impact

This vulnerability has been assigned a CVSS v3.1 Base Score of 8.8 (High severity). Successful exploitation of CVE-2026-66039 allows an attacker to execute arbitrary code within the context of the application that processes the malicious CAF file. As FFmpeg is a widely utilized multimedia framework across diverse applications such as media players, video converters, streaming software, and operating systems (Windows, Linux, macOS), a broad spectrum of systems are potentially exposed to this remote code execution vector. A successful compromise could lead to sensitive data exfiltration, full system control, or further lateral movement within a network, depending on the privileges of the exploited process. The pervasive nature of FFmpeg suggests a substantial number of devices and systems could be impacted globally.

## Recommendation

* Patch CVE-2026-66039 by updating all affected FFmpeg installations to a version beyond 8.1.2, or ensure that commit `aafb5c6` has been applied.
* Implement strict input validation and sanitization for all multimedia files, particularly CAF files, that are processed by applications utilizing FFmpeg.
* Educate users about the risks of opening or processing untrusted or unsolicited CAF files from unknown or suspicious sources.
