---
title: Heap-based Buffer Overflow in FFmpeg hvcC Box Writer
slug: 2026-08-ffmpeg-heap-overflow
description: FFmpeg versions prior to commit acf5d7c contain a heap-based buffer overflow in the hvcC box writer that can be triggered during HEVC file muxing, potentially leading to arbitrary code execution.
date: "2026-08-19T18:38:30Z"
lastmod: "2026-08-19T18:38:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - memory-corruption
vendors:
  - FFmpeg
products:
  - FFmpeg
  - FFmpeg (< 1cdeb3c)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A crafted HEVC input file triggers the overflow during muxing.
    confidence_band: high
cves:
  - id: CVE-2026-75141
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75141
  - https://code.ffmpeg.org/FFmpeg/FFmpeg/commit/acf5d7cdc1f9ae8752c23e1ea8d7f355ed780781
  - https://www.vulncheck.com/advisories/ffmpeg-heap-buffer-overflow-in-hvcc-box-writer-via-hevc-muxing
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75142
  - https://code.ffmpeg.org/FFmpeg/FFmpeg/commit/9d786e4b5e9b8482651928574de33772aeee7be1
  - https://www.vulncheck.com/advisories/ffmpeg-stack-buffer-overflow-in-mpeg-ps-muxer-via-mpegenc-c
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75144
  - https://code.ffmpeg.org/FFmpeg/FFmpeg/commit/1cdeb3c4e7f1f8566d846b9b451e01c376398818
  - https://www.vulncheck.com/advisories/ffmpeg-heap-buffer-overflow-in-vc-2-dirac-rtp-packetizer
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update FFmpeg libraries to commit acf5d7c or later in all media processing services.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-75141 remediation via commit acf5d7c
  mitigation_plan:
    - priority: immediate
      action: Isolate media transcoding workloads using untrusted input from main production systems.
      owner: IT Operations
      addresses: CVE-2026-75141
      evidence: General mitigation for input-based exploitation
updates:
  - at: "2026-08-19T18:38:38Z"
    level: L2
    summary: added coverage for FFmpeg
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75142
  - at: "2026-08-19T18:38:46Z"
    level: L2
    summary: added coverage for FFmpeg (< 1cdeb3c)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75144
---

A heap-based buffer overflow vulnerability (CVE-2026-75141) exists in the FFmpeg media processing library, specifically within the hvcC (HEVC configuration record) box writer. The vulnerability is triggered when processing an HEVC file that contains an excessive number of Network Abstraction Layer (NAL) units of a single type, exceeding the capacity of the internal count field. This integer overflow results in a heap-based buffer overflow during the muxing process. An attacker can leverage this flaw by providing a specially crafted HEVC file to an application that utilizes affected versions of FFmpeg. Successful exploitation could allow for arbitrary code execution or cause an application crash. Given FFmpeg's ubiquity in media transcoding pipelines, software players, and web-based processing services, this vulnerability poses a significant risk to any environment that processes untrusted video input.

## Attack Chain

1. Attacker crafts a malicious HEVC video file containing an oversized count of specific NAL units.
2. Attacker identifies a target application or service that utilizes the affected FFmpeg library for media processing.
3. The target application receives the malicious HEVC file via upload, network stream, or file system access.
4. The application passes the malicious file to the FFmpeg library for muxing or transcoding operations.
5. The hvcC box writer component within FFmpeg attempts to process the HEVC configuration record.
6. The integer overflow occurs during the calculation of the NAL unit count, leading to an incorrect buffer size allocation.
7. Writing the configuration record triggers a heap-based buffer overflow, overwriting adjacent memory.
8. Final objective is achieved, resulting in either a denial of service (crash) or potentially arbitrary code execution within the context of the target application.

## Impact

The vulnerability allows an attacker to achieve arbitrary code execution or denial of service on systems processing crafted HEVC content. Given the widespread integration of FFmpeg into multimedia applications, content management systems, and transcoding servers, this represents a significant security risk for any organization handling user-supplied media files.

## Recommendation

* Patch FFmpeg by updating to or beyond commit acf5d7cdc1f9ae8752c23e1ea8d7f355ed780781.
* Audit applications within the environment that utilize FFmpeg for video processing and ensure they are compiled against or linked to the patched library version.
* Implement strict input validation and sandboxing for media processing pipelines to mitigate risks from processing untrusted HEVC files.
