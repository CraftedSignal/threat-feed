---
title: Pillow Decompression Bomb Bypass via PCF Font Loading
slug: 2026-07-pillow-pcf-font-bomb-bypass
description: A vulnerability in Pillow's `PcfFontFile._load_bitmaps()` function allows for a decompression bomb check bypass when loading PCF fonts. Attacker-controlled glyph dimensions from the PCF `METRICS` section are passed directly to `Image.frombytes()` without validation, leading to excessive memory allocation. This can be exploited to cause denial of service (resource exhaustion) through either persistent attacks by providing matching bitmap data or transient attacks by providing a small PCF file with large declared dimensions, leading to a large C-heap buffer allocation before an exception. Systems loading PCF fonts from untrusted sources are at risk.
date: "2026-07-20T21:15:44Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability-exploitation
  - python
vendors:
  - python-pillow
products:
  - Pillow (< 12.3.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: A vulnerability in Pillow's PcfFontFile._load_bitmaps() function allows for a decompression bomb check bypass when loading PCF fonts. Attacker-controlled glyph dimensions from the PCF METRICS section are passed directly to Image.frombytes() without validation, leading to excessive memory allocation. This can be exploited to cause denial of service (resource exhaustion)
    confidence_band: high
cves:
  - id: CVE-2026-54059
    cvss: 7.5
    epss: 0.00354
references:
  - https://github.com/advisories/GHSA-8v84-f9pq-wr9x
---

A critical vulnerability, tracked as CVE-2026-54059, has been identified in the Python Imaging Library (Pillow) affecting versions prior to 12.3.0. The flaw resides within the `PcfFontFile._load_bitmaps()` function, which is responsible for loading PCF font files. Attackers can craft a malicious PCF font file where the `METRICS` section declares excessively large glyph dimensions (up to 65,535 x 131,070 pixels). These attacker-controlled dimensions are then passed directly to `Image.frombytes()` without first undergoing the `_decompression_bomb_check()`. This bypass allows for a decompression bomb, potentially leading to massive memory allocations (over 1 GB per glyph) and resulting in a denial-of-service (DoS) condition due to resource exhaustion. The vulnerability can manifest as either a transient attack, where a small PCF file triggers a large allocation before a `ValueError`, or a persistent attack, where a larger PCF file with matching bitmap data leads to a sustained memory burden. Any service or application that processes PCF font files from untrusted sources using vulnerable Pillow versions is susceptible. This issue was confirmed unpatched as of June 7, 2026, on the `main` branch.

## Attack Chain

1. An attacker crafts a specially designed PCF (Portable Compiled Format) font file.
2. The malicious PCF file includes a `METRICS` section that specifies unusually large dimensions for the font glyphs, such as 65535 for width and 131070 for height.
3. The attacker delivers this malicious PCF file to a target system or application. This could be via email, file upload, or any method allowing the application to process an untrusted font.
4. A vulnerable application using Pillow (versions prior to 12.3.0) attempts to load the malicious PCF font file using the `PcfFontFile` class.
5. During the font loading process, specifically within `PcfFontFile._load_bitmaps()`, the declared large `xsize` and `ysize` values are read from the `METRICS` section.
6. These large dimensions are then directly passed to `Image.frombytes()` without invoking Pillow's internal `_decompression_bomb_check()`, which normally prevents excessive memory allocations.
7. `Image.frombytes()` internally calls `Image.new()`, which proceeds to allocate a significantly large C-heap buffer (potentially over 1 GB) based on the attacker-controlled dimensions.
8. This massive memory allocation consumes system resources, leading to resource exhaustion and a denial-of-service (DoS) condition for the affected application or system.

## Impact

This vulnerability poses a significant availability risk to any service or application that loads PCF fonts from untrusted sources. Attackers can trigger high-impact denial-of-service (DoS) conditions by causing excessive memory allocation, with the potential for over 1.07 GB of memory to be consumed per glyph within a font file. There are no inherent limits to the number of glyphs per font file or the number of font files an attacker could submit, potentially leading to complete system resource exhaustion. The vulnerability allows for both transient memory spikes, where a small 148-byte malicious file can trigger a gigabyte-scale allocation before an error, and persistent consumption if the bitmap data is also crafted to match. The confidentiality and integrity of data are not directly affected by this vulnerability.

## Recommendation

* Patch CVE-2026-54059 by updating the `pip/pillow` package to version 12.3.0 or later immediately.
* Configure applications and services to explicitly avoid loading PCF font files from untrusted or external sources.
* Ensure that any Python environment running applications that process image or font files has `Pillow` updated to a non-vulnerable version.
