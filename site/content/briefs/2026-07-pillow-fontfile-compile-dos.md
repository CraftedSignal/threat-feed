---
title: Pillow FontFile.compile() Vulnerability Bypasses Decompression Checks Leading to DoS (CVE-2026-54060)
slug: 2026-07-pillow-fontfile-compile-dos
description: A vulnerability, CVE-2026-54060, in the Pillow library's `FontFile.compile()` method allows attackers to craft malicious BDF or PCF font files that bypass standard decompression bomb checks, causing an unchecked, massive memory allocation when processed, which can lead to a Denial of Service (DoS) via an Out-Of-Memory (OOM) crash in vulnerable applications.
date: "2026-07-20T21:14:58Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - python
  - pillow
  - software-supply-chain
vendors:
  - Pillow Project
products:
  - Pillow (< 12.3.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This can lead to excessive memory consumption, potentially reaching gigabytes, and ultimately cause a Denial of Service (DoS) through an Out-Of-Memory (OOM) crash in applications processing these fonts.
    confidence_band: high
cves:
  - id: CVE-2026-54060
    cvss: 7.5
    epss: 0.00361
references:
  - https://github.com/advisories/GHSA-5x94-69rx-g8h2
---

A critical vulnerability, tracked as CVE-2026-54060, has been identified in the Pillow image processing library (versions prior to 12.3.0). Specifically, the `FontFile.compile()` method, used by both `BdfFontFile` and `PcfFontFile` to assemble per-glyph images into a single combined bitmap, fails to invoke the `Image._decompression_bomb_check()`. This oversight allows an attacker to craft a malicious font file (e.g., BDF or PCF format) where individual glyphs are small enough to evade existing checks, but their combined size results in an uncontrolled, massive memory allocation upon compilation. For instance, a font with 256 glyphs, each claiming a height of 65,535 pixels, can trigger an allocation of approximately 1.6 GB, potentially reaching 13.4 billion pixels. This vulnerability can be triggered in applications that process user-supplied font files, such as web font preview services or server-side font renderers, leading to application crashes and Denial of Service (DoS) due to Out-Of-Memory (OOM) errors.

## Attack Chain

1. An attacker crafts a malicious font file (e.g., a BDF or PCF file) containing multiple glyphs, each configured with specific dimensions (e.g., maximum PCF glyph height of 65,535 pixels and width of 800 pixels). These individual glyph dimensions are carefully chosen to remain below Pillow's default `DecompressionBombWarning` and `DecompressionBombError` thresholds.
2. The attacker delivers this crafted font file to a vulnerable application that uses the Pillow library for font processing. This could occur via an upload mechanism to a web font preview service, as part of a document loaded by a server-side rendering engine, or through a font pipeline.
3. The vulnerable application loads the crafted font file using Pillow's `BdfFontFile.BdfFontFile(fp)` or `PcfFontFile.PcfFontFile(fp)` methods.
4. Subsequently, the application attempts to process or convert the loaded font, for example, by calling `to_imagefont()` or `save(filename)` on the font object.
5. This action internally triggers the `FontFile.compile()` method, which is responsible for assembling all per-glyph images into a single, large combined bitmap.
6. Within the `compile()` method, an `Image.new("1", (xsize, ysize))` call is executed to create the combined bitmap, but critically, it bypasses the `Image._decompression_bomb_check()` that would typically prevent excessively large allocations.
7. The unchecked allocation results in a massive memory consumption spike (e.g., 1.6 GB for 256 glyphs at max PCF height, representing 13.4 billion pixels). This rapid and excessive memory request often exceeds available system resources.
8. The application process then crashes due to an Out-Of-Memory (OOM) error, rendering the service unavailable and achieving a Denial of Service (DoS) for the affected system.

## Impact

The primary impact of CVE-2026-54060 is a high availability risk, leading to Denial of Service (DoS). Exploiting this vulnerability can cause applications utilizing the Pillow library for font processing to consume an unchecked, massive amount of memory, resulting in Out-Of-Memory (OOM) crashes. Affected scenarios include web services providing font previews, server-side font renderers, or any font pipeline that loads and processes BDF or PCF font files from untrusted sources. For example, a crafted font file can trigger a ~1.6 GB memory allocation, potentially up to 75 times the normal `DecompressionBombError` threshold, which is sufficient to crash most server-side processes. There is no observed impact on confidentiality or integrity.

## Recommendation

* Patch all systems using the Pillow library to version 12.3.0 or later immediately to address CVE-2026-54060.
* Implement strict input validation and sanitization for any user-supplied font files before processing them with Pillow, especially for BDF and PCF formats.
* Monitor application memory usage and process health, particularly for services that handle user-uploaded or externally sourced font files, to detect abnormal memory spikes that could indicate an attempted exploitation of CVE-2026-54060.
