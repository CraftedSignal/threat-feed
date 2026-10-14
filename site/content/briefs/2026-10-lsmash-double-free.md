---
title: L-SMASH Double Free Vulnerability in NALU Importer
slug: 2026-10-lsmash-double-free
description: L-SMASH versions through 2.14.5 contain a double free vulnerability in the NALU importer, allowing remote attackers to trigger heap corruption via a crafted Annex-B elementary stream.
date: "2026-10-14T16:36:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:l-smash_project:l-smash:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
vendors:
  - L-SMASH
products:
  - L-SMASH (<= 2.14.5)
cves:
  - id: CVE-2026-110599
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110599
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade L-SMASH library to a version beyond 2.14.5 to patch CVE-2026-110599.
      owner: IT Operations
      addresses: CVE-2026-110599
      evidence: NVD advisory for CVE-2026-110599
---

L-SMASH, a library used for handling ISO Base Media File Format (ISO-BMFF) streams, is vulnerable to a double free condition (CVE-2026-110599) in the `hevc_setup_first_summary()` and `h264_setup_first_summary()` functions located in `importer/nalu_imp.c`. The vulnerability arises when the library handles a malformed Annex-B elementary stream that lacks a parseable Sequence Parameter Set (SPS). When processing such a stream via `lsmash_read_file()` or related utility tools like `boxdumper`, `remuxer`, or `muxer`, the error handling path incorrectly frees codec-specific objects that have already been released. This behavior leads to heap corruption, which may result in application crashes or potentially arbitrary code execution depending on the heap layout and application context. Organizations integrating L-SMASH into video processing pipelines or media container conversion tools are at risk if they process untrusted user-supplied media files.

## Attack Chain

1. Attacker generates a malicious Annex-B elementary stream missing a valid Sequence Parameter Set (SPS).
2. Attacker provides the malicious media file to a target application utilizing L-SMASH for parsing.
3. The target application calls `lsmash_read_file()` or a similar L-SMASH tool to process the input.
4. The library reaches the `hevc_setup_first_summary()` or `h264_setup_first_summary()` function during the NALU import process.
5. The error-handling routine triggered by the missing SPS fails to validate the state of memory.
6. The library attempts a double free operation on the codec-specific object pointer.
7. The application experiences heap corruption or an abnormal termination (crash) due to memory management inconsistency.

## Impact

Successful exploitation results in application instability and service disruption, which may be leveraged to perform a denial-of-service (DoS) attack against media-processing servers. In specific configurations, the resulting heap corruption could be leveraged to achieve arbitrary code execution. The impact is significant for media production environments, content delivery networks, and video transcoding services that process external input files automatically.

## Recommendation

* Update all instances of L-SMASH to a version post-dating 2.14.5 that contains the fix for CVE-2026-110599.
* Implement input validation for media files before passing them to the L-SMASH library to ensure they contain a valid SPS header.
* Run media processing tasks in isolated, low-privileged containers to limit the impact of potential heap exploitation.
* Monitor process logs for abnormal terminations or segmentation faults occurring during media parsing operations.
