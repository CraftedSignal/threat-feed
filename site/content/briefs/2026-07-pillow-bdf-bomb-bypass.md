---
title: Pillow BdfFontFile Decompression Bomb Bypass Vulnerability
slug: 2026-07-pillow-bdf-bomb-bypass
description: A vulnerability (CVE-2026-55379) in Pillow's BdfFontFile component allows attackers to craft a malicious BDF font file with oversized BBX dimensions and an empty BITMAP section, bypassing documented decompression bomb protection and causing the Image.new() function to silently allocate large amounts of memory in the C-heap, leading to resource exhaustion and denial-of-service for applications processing untrusted BDF fonts.
date: "2026-07-20T21:14:14Z"
lastmod: "2026-07-20T21:21:04Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*
tags:
  - pillow
  - vulnerability
  - denial-of-service
  - python
vendors:
  - Pillow
products:
  - pillow (< 12.3.0)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: A BDF glyph with BBX 20000 20000 and an empty BITMAP section causes Image.new('1', (20000, 20000)) to allocate 50 MB of C-heap silently.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any public endpoint accepting image uploads is affected
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: a single 1,037-byte malicious `.gd` file causes the host process to attempt a ~4.3 GB C-heap allocation. On systems with insufficient memory this crashes the process. Repeatable — attacker can loop requests to keep the server down.
    confidence_band: high
cves:
  - id: CVE-2026-55379
    cvss: 7.5
    epss: 0.00364
references:
  - https://github.com/advisories/GHSA-45hq-cxwh-f6vc
  - https://github.com/advisories/GHSA-phj9-mv4w-65pm
updates:
  - at: "2026-07-20T21:21:04Z"
    level: L1
    summary: 'merged source coverage: Pillow GdImageFile Decompression Bomb Bypass Leads to Denial of Service'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-phj9-mv4w-65pm
---

The Pillow imaging library, a critical component in many Python applications, contains a denial-of-service vulnerability (CVE-2026-55379) in its `BdfFontFile` component, affecting versions prior to 12.3.0. This flaw allows an attacker to bypass Pillow's documented decompression bomb protection mechanism by crafting a malicious BDF font file. Specifically, when a BDF file defines a glyph with excessively large dimensions in its `BBX` field (e.g., `20000 20000`) but an empty `BITMAP` section, the `Image.frombytes()` call fails. The fallback `Image.new()` function then allocates a substantial amount of memory in the C-heap (e.g., 50 MB for a single glyph) without performing the necessary `_decompression_bomb_check()`. This silent, unbounded memory allocation, especially when combined with multiple such glyphs, can quickly exhaust system resources, leading to a denial-of-service condition for any application that processes untrusted BDF fonts.

## Attack Chain

1. An attacker crafts a specially malicious BDF font file containing glyph definitions.
2. For each target glyph, the attacker sets an extremely large `BBX` (bounding box) width and height, such as `BBX 20000 20000`.
3. The attacker ensures the `BITMAP` section for these glyphs is left empty, forcing a specific error condition during parsing.
4. A vulnerable application, using a Pillow version older than 12.3.0, attempts to load this malicious BDF font file via `ImageFont.load()` or `BdfFontFile()`.
5. During the `bdf_char()` function's processing of the malicious glyph, `Image.frombytes()` is called.
6. Due to the empty `BITMAP` section, `Image.frombytes()` raises a `ValueError`.
7. The code then executes a fallback: `Image.new("1", (width, height))` is called with the attacker-controlled large dimensions.
8. Crucially, `Image.new()` in this specific code path does not invoke Pillow's `_decompression_bomb_check()`, leading to silent, massive C-heap memory allocation (e.g., ~50 MB per `20000x20000` glyph). Repeated allocations from multiple glyphs (e.g., 256 glyphs allocating ~1.95 GB) cause resource exhaustion and a denial-of-service condition for the application.

## Impact

The primary impact of this vulnerability is a high risk to availability. An attacker can trigger unbounded memory allocation in applications that process untrusted BDF font files. A single malicious BDF glyph can cause tens of megabytes of memory allocation, and multiple glyphs can quickly lead to gigabytes of memory consumption (e.g., 256 glyphs causing 1.95 GB allocation) in the C-heap. This resource exhaustion results in denial-of-service, crashing the application or the host system. Any service loading BDF fonts from untrusted sources (e.g., `ImageFont.load("user.bdf")`, `BdfFontFile(fp)`) is affected, regardless of the underlying operating system. The allocated glyph images persist in memory for the lifetime of the font object, preventing immediate memory recovery.

## Recommendation

* Patch affected systems by upgrading the Pillow library to version 12.3.0 or later immediately to address CVE-2026-55379.
* Implement input validation and sanitization for all BDF font files processed by applications to prevent untrusted or malformed files from being loaded, thereby mitigating the risk described in CVE-2026-55379.
* Monitor applications that process image or font files for sudden, anomalous spikes in memory consumption, which could indicate a resource exhaustion attack exploiting this type of vulnerability.
