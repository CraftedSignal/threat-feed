---
title: SixLabors ImageSharp TIFF Heap Out-of-Bounds Write
slug: 2026-10-imagesharp-tiff-oob
description: A heap out-of-bounds write vulnerability (CVE-2026-106118) in the SixLabors ImageSharp library allows remote attackers to cause a process crash or potentially execute arbitrary code by supplying a maliciously crafted tiled TIFF image using fax compression.
date: "2026-10-07T16:58:35Z"
lastmod: "2026-10-07T22:51:21Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:sixlabors:imagesharp:*:*:*:*:*:*:*:*
tags:
  - cve-2026-106118
  - heap-overflow
  - imagesharp
  - dos
  - vulnerability
  - cve-2026-106117
  - image-processing
  - memory-corruption
  - cve-2026-106115
  - cve-2026-106112
vendors:
  - SixLabors
products:
  - ImageSharp (>= 3.0.0, < 4.1.1)
  - ImageSharp (3.0.0 - 4.1.0)
  - ImageSharp (>= 2.1.0, <= 4.1.1)
  - ImageSharp (4.0.0-4.1.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker can craft a malicious TIFF file to trigger a deterministic process crash (DoS) or potentially achieve remote code execution via heap corruption.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The processing of malformed ICC profiles triggers unsafe memory operations, leading to forced application termination.
    confidence_band: high
cves:
  - id: CVE-2026-106118
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-v76p-62qx-wwq2
  - https://github.com/advisories/GHSA-jj3q-cwqj-842r
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106117
  - https://github.com/advisories/GHSA-jjfr-hcj7-qf5w
  - https://github.com/advisories/GHSA-ffp7-56pq-64mr
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade ImageSharp to version 4.1.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrading to 4.1.1 for security fix
  mitigation_plan:
    - priority: immediate
      action: Identify and restrict processing of tiled TIFF files in untrusted input channels
      owner: SOC
      addresses: CVE-2026-106118
      evidence: Vulnerability only triggers on tiled TIFFs with T4/T6/MH compression
updates:
  - at: "2026-10-07T16:58:47Z"
    level: L1
    summary: added coverage for ImageSharp (3.0.0 - 4.1.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-jj3q-cwqj-842r
  - at: "2026-10-07T22:51:11Z"
    level: L1
    summary: added coverage for ImageSharp (>= 2.1.0, <= 4.1.1)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-jjfr-hcj7-qf5w
  - at: "2026-10-07T22:51:21Z"
    level: L1
    summary: added coverage for ImageSharp (4.0.0-4.1.1)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-ffp7-56pq-64mr
---

SixLabors ImageSharp, a popular cross-platform image processing library for .NET, contains a heap-based out-of-bounds write vulnerability (CVE-2026-106118) within its TIFF decoding component. The issue originates from a mismatch between buffer allocation and the fax decompressor logic when processing tiled TIFF images. Specifically, the library allocates buffers based on `TileWidth`, but the `T4TiffCompression` and `T6TiffCompression` decompressors incorrectly utilize the `frame.Width` of the full image for write operations. 

This logic failure causes the decompressor to write scanline data significantly past the allocated memory boundaries. Because the write operations lack bounds checking, an attacker can control the amount of memory overwritten by crafting specific fax-compressed tiles. This defect, verified in versions 3.0.0 through 4.1.0, results in a deterministic process crash (Denial of Service) or provides a potential primitive for memory corruption and remote code execution in any application utilizing ImageSharp to process untrusted TIFF files.

## Attack Chain

1. Attacker crafts a malicious TIFF file with T4/T6/MH compression enabled.
2. Attacker specifies an unusually high `ImageWidth` (e.g., 4,000,000 pixels) while defining small `TileWidth` and `TileHeight` dimensions (e.g., 16x16) in the TIFF header.
3. The victim application calls `Image.Load(stream)` on the malicious TIFF file.
4. The library's `TiffDecoderCore` determines the file is tiled and enters `DecodeTilesChunky`.
5. The library allocates a tile buffer sized strictly for the `TileWidth`, which is significantly smaller than the logical width expected by the decompressor.
6. The `TiffDecompressorsFactory` incorrectly initializes the fax decompressor with the full `frame.Width`.
7. During decompression, the `BitWriterUtils` performs linear writes of the pixel scanlines into the undersized buffer, causing a heap memory overflow.
8. The process crashes due to an `AccessViolationException` or remains in a silent heap-corruption state depending on the pixel data content.

## Impact

Successful exploitation results in an immediate Denial of Service (DoS) for the host process. Given the attacker-controllable length and width of the out-of-bounds write, this vulnerability creates a high-risk surface for potential remote code execution (RCE) in any server-side application or desktop utility that processes tiled TIFF imagery, such as image converters, web-based media upload services, or document management systems.

## Recommendation

1. Patch immediately by upgrading ImageSharp to version 4.1.1 or later, which addresses the incorrect decompressor width assignment and adds proper bounds checking to the write operations.
2. Implement an immediate block or sanitization layer for any incoming TIFF files that exhibit unusual compression configurations (T4/T6) combined with tiled layouts until patching is completed.
3. Integrate the suggested regression tests - specifically testing `Compression` modes 2, 3, and 4 against tiled inputs with `TileWidth` less than the total `ImageWidth` - into your CI/CD pipeline to detect similar memory safety regressions.
