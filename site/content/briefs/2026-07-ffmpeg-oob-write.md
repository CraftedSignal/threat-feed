---
title: FFmpeg Out-of-Bounds Write Vulnerability CVE-2026-65704
slug: 2026-07-ffmpeg-oob-write
description: An out-of-bounds write vulnerability, identified as CVE-2026-65704, in FFmpeg through version 8.1.2 allows attackers to cause heap corruption by providing a specially crafted ffconcat file processed with the '-safe 0' flag.
date: "2026-07-23T20:21:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - ffmpeg
  - out-of-bounds-write
  - heap-corruption
vendors:
  - FFmpeg
products:
  - FFmpeg (through 8.1.2)
cves:
  - id: CVE-2026-65704
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65704
---

A critical out-of-bounds write vulnerability, CVE-2026-65704, has been identified in FFmpeg, impacting all versions up to and including 8.1.2. This flaw allows a remote attacker to cause heap corruption by processing a maliciously crafted `ffconcat` file, specifically when FFmpeg is invoked with the `-safe 0` flag. The vulnerability resides within the `TY demuxer`'s `demux_audio()` function, which fails to perform proper bounds checking when decrementing packet size. This can lead to a negative size value being passed to `memcpy()` in `shorten_decode_frame()`, causing the value to wrap to near `SIZE_MAX`. Consequently, `memcpy()` attempts to read beyond its allocated source memory and write far beyond the Shorten decoder's bitstream buffer, resulting in heap corruption. Organizations utilizing FFmpeg in multimedia processing pipelines, especially those that process untrusted media files or use the `-safe 0` flag, are at risk.

## Attack Chain

1. An attacker crafts a malicious `ffconcat` file designed to trigger the out-of-bounds write.
2. The crafted `ffconcat` file includes specific parameters within its `TY demuxer` section to exploit the vulnerability.
3. The attacker delivers this malicious file to a victim system or application that uses FFmpeg.
4. The victim's system processes the malicious `ffconcat` file using FFmpeg, crucially with the `-safe 0` flag enabled.
5. During demuxing, the FFmpeg `TY demuxer`'s `demux_audio()` function processes the specially crafted data.
6. The `demux_audio()` function decrements a packet size value without proper bounds checking, leading to a negative result.
7. This negative size value is then passed to the `memcpy()` function within `shorten_decode_frame()`.
8. The negative size value is converted to an unsigned `size_t` type, wrapping to a very large positive number (near `SIZE_MAX`), causing `memcpy()` to attempt to read and write far outside the intended buffer boundaries, leading to heap corruption.

## Impact

Successful exploitation of CVE-2026-65704 leads to heap corruption. This type of memory corruption can result in various severe consequences, including denial of service (DoS) by crashing the FFmpeg process or the application embedding it. More critically, heap corruption often creates conditions that can be leveraged for arbitrary code execution (RCE) by overwriting critical memory structures, allowing an attacker to run malicious code with the privileges of the affected FFmpeg process. This could compromise the integrity, confidentiality, and availability of data and systems processing untrusted media files. While specific victim counts are not available, any system processing untrusted media with vulnerable FFmpeg versions and the `-safe 0` flag is at risk.

## Recommendation

* Upgrade FFmpeg to a patched version beyond 8.1.2 immediately to remediate CVE-2026-65704.
* Avoid processing untrusted `ffconcat` files from external sources, especially when FFmpeg is invoked with the `-safe 0` flag.
* Review all FFmpeg invocations in your environment and remove the `-safe 0` flag if it is not absolutely necessary, as it bypasses critical security checks.
