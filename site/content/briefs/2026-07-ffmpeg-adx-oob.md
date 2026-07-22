---
title: FFmpeg ADX Audio Decoder Out-of-Bounds Memory Access Vulnerability
slug: 2026-07-ffmpeg-adx-oob
description: A high-severity out-of-bounds memory access vulnerability, tracked as CVE-2026-64835, exists in FFmpeg versions 4.4 through 8.1.2 within the ADX audio decoder, allowing attackers to trigger both out-of-bounds reads and writes by supplying a crafted ADX or AAX audio file with a mid-stream channel layout change, potentially leading to denial of service, information disclosure, or arbitrary code execution.
date: "2026-07-22T18:24:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - ffmpeg
  - audio-codec
  - memory-corruption
  - denial-of-service
  - remote-code-execution
vendors:
  - FFmpeg
products:
  - FFmpeg (4.4-8.1.2)
cves:
  - id: CVE-2026-64835
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-64835
---

FFmpeg versions 4.4 through 8.1.2 are affected by a high-severity out-of-bounds memory access vulnerability, identified as CVE-2026-64835. This flaw resides specifically within the ADX audio decoder, located in the `libavcodec/adxdec.c` file. The vulnerability allows an attacker to trigger out-of-bounds reads and writes by providing a specially crafted ADX or AAX audio file. This malicious file must include a mid-stream channel layout change delivered via `AV_PKT_DATA_NEW_EXTRADATA` side data. When processed, the `adx_decode_frame` function re-parses the stream header but critically fails to update its internal channel state. This oversight causes subsequent decoding operations to access the `prev[]` state array using a stale channel count, leading to memory corruption. This vulnerability can affect any system or application utilizing FFmpeg to process ADX or AAX audio files within the specified version range.

## Attack Chain

1. An attacker crafts a malicious ADX or AAX audio file containing `AV_PKT_DATA_NEW_EXTRADATA` side data that specifies a mid-stream channel layout change.
2. The crafted audio file is delivered to a victim system or application, often via download, email, or a malicious website.
3. The victim system or application uses a vulnerable FFmpeg version (4.4 through 8.1.2) to process the crafted audio file.
4. During processing, the `adx_decode_frame` function within `libavcodec/adxdec.c` encounters the `AV_PKT_DATA_NEW_EXTRADATA` side data and re-parses the stream header.
5. The `adx_decode_frame` function fails to correctly update its internal channel state following the re-parsing.
6. Subsequent decoding operations attempt to access the `prev[]` state array using the outdated (stale) channel count, resulting in an out-of-bounds memory access.
7. This out-of-bounds access can lead to application crashes (denial of service), information disclosure, or, in certain exploit scenarios, arbitrary code execution within the context of the FFmpeg process.

## Impact

The successful exploitation of CVE-2026-64835 can lead to severe consequences for systems processing ADX or AAX audio files with vulnerable FFmpeg versions. The out-of-bounds memory access can directly cause the FFmpeg application to crash, resulting in a denial of service for any media processing functionality. Depending on the memory layout and the specifics of the out-of-bounds read/write, this vulnerability could also facilitate information disclosure, allowing attackers to access sensitive data, or, in more advanced scenarios, lead to arbitrary code execution. This could grant an attacker control over the compromised system, making it a critical risk for media processing platforms, content creation tools, and any software relying on FFmpeg for audio decoding.

## Recommendation

* Patch CVE-2026-64835 immediately by updating all instances of FFmpeg to a version beyond 8.1.2.
* Implement strict validation and sanitization for all incoming audio files, especially ADX and AAX formats, to prevent the ingestion of crafted malicious files that could trigger CVE-2026-64835.
