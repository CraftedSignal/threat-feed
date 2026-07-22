---
title: FFmpeg Out-of-Bounds Read Vulnerability in S/PDIF Muxer (CVE-2026-64833)
slug: 2026-07-ffmpeg-oob-read
description: FFmpeg versions 0.7.1 through 8.1.2 contain an out-of-bounds read vulnerability in the S/PDIF muxer, allowing attackers to exploit a missing bounds check in the `spdif_header_dts4` function by supplying a crafted DTS stream with an oversized `core_size` value during S/PDIF re-muxing, leading to unauthorized memory reads beyond the packet buffer and potential information disclosure or denial of service.
date: "2026-07-22T18:18:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - out-of-bounds-read
  - ffmpeg
vendors:
  - FFmpeg
products:
  - FFmpeg (0.7.1 - 8.1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can exploit the missing bounds check in the spdif_header_dts4 function by providing a malicious DTS-HD audio stream during S/PDIF re-muxing to trigger unauthorized memory reads beyond the packet buffer.
    confidence_band: med
cves:
  - id: CVE-2026-64833
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64833
  - https://code.ffmpeg.org/FFmpeg/FFmpeg/commit/6f80e2765492700622596af720534cef33dd31b4
  - https://code.ffmpeg.org/FFmpeg/FFmpeg/pulls/23661
  - https://www.vulncheck.com/advisories/ffmpeg-out-of-bounds-read-via-s-pdif-muxer-spdifenc-c
---

FFmpeg versions 0.7.1 through 8.1.2 are affected by an out-of-bounds read vulnerability, identified as CVE-2026-64833, residing within the S/PDIF muxer component. This flaw stems from a missing bounds check in the `spdif_header_dts4` function. An attacker can exploit this by crafting a malicious DTS-HD audio stream where the `core_size` value is intentionally larger than the actual packet length. When this specially crafted stream is processed by a vulnerable FFmpeg instance during S/PDIF re-muxing, it triggers an unauthorized read operation beyond the legitimate buffer boundaries. The vulnerability can lead to information disclosure from adjacent memory regions or result in a denial of service due to an application crash. This affects applications that utilize FFmpeg for audio processing and re-muxing of DTS streams, potentially impacting a wide range of media processing and streaming services.

## Attack Chain

1. An attacker crafts a malicious DTS-HD audio stream file.
2. The crafted stream's header includes a `core_size` value that is intentionally larger than the actual data packet length.
3. The attacker delivers this malicious DTS-HD audio file to a victim system running a vulnerable FFmpeg version.
4. The victim's application processes the malicious file, initiating S/PDIF re-muxing via FFmpeg.
5. FFmpeg's S/PDIF muxer attempts to parse the DTS stream.
6. Within the `spdif_header_dts4` function, the missing bounds check allows a read operation to proceed using the oversized `core_size` value.
7. This operation accesses memory beyond the allocated buffer for the DTS packet, resulting in an out-of-bounds read.
8. The out-of-bounds read leads to potential information disclosure (e.g., sensitive memory contents) or denial of service (e.g., application crash) on the victim system.

## Impact

The successful exploitation of CVE-2026-64833 can lead to a low impact on confidentiality and a high impact on availability, as indicated by its CVSS 3.1 score of 7.1. An attacker could potentially read sensitive information from memory beyond the intended buffer, though the scope of information disclosure is limited. More critically, the vulnerability can cause the FFmpeg process, and by extension, the application utilizing it, to crash, leading to a denial of service. The widespread use of FFmpeg across various media applications, streaming platforms, and development environments means that a broad range of systems could be vulnerable if they process untrusted DTS audio streams.

## Recommendation

* Immediately update all installations of FFmpeg to a version beyond 8.1.2 to remediate CVE-2026-64833.
* Implement strict input validation and sanitization for all incoming DTS-HD audio streams, especially those from untrusted sources, to prevent the ingestion of maliciously crafted files.
* Monitor applications utilizing FFmpeg for unexpected crashes or abnormal memory usage patterns that could indicate an attempted or successful exploitation of this vulnerability.
