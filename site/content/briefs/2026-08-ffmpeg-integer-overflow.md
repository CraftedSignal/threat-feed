---
title: Heap Buffer Overflow in FFmpeg DVB Subtitle Parser
slug: 2026-08-ffmpeg-integer-overflow
description: FFmpeg versions 0.5 through 8.9 are vulnerable to a signed integer overflow in the DVB subtitle parser that can be triggered via a crafted WTV file to achieve remote code execution.
date: "2026-08-06T23:31:28Z"
lastmod: "2026-08-07T15:22:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - memory-corruption
  - ffmpeg
vendors:
  - FFmpeg
products:
  - FFmpeg (0.5 to < 9.0)
  - FFmpeg (4.4-8.x)
  - FFmpeg
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The overflow causes the bounds-check guard expression to wrap to INT_MIN, bypassing the PARSE_BUF_SIZE comparison and invoking memcpy() with attacker-controlled data into a heap buffer, resulting in an out-of-bounds heap write and potential memory corruption or code execution.
    confidence_band: high
cves:
  - id: CVE-2026-70628
    cvss: 7.8
  - id: CVE-2026-70632
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70628
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70632
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2700
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch FFmpeg libraries to 9.0 or later across all software dependencies.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-70628 advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict processing of WTV files from untrusted sources.
      owner: Security Engineering
      addresses: CVE-2026-70628
      evidence: Source notes WTV file as trigger for overflow.
updates:
  - at: "2026-08-06T23:31:35Z"
    level: L2
    summary: added coverage for FFmpeg (4.4-8.x)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70632
  - at: "2026-08-07T15:22:40Z"
    level: L2
    summary: added CVE-2026-70632
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2700
---

FFmpeg versions ranging from 0.5 up to, but not including, 9.0 contain a critical signed integer overflow vulnerability within the DVB subtitle parser located in the `libavcodec/dvbsub_parser.c` source file. The vulnerability is triggered when the parser processes a maliciously crafted WTV (Windows Recorded TV) container file. During parsing, the logic responsible for bounds checking is susceptible to a signed integer overflow. Specifically, the guard expression wraps to a negative value (INT_MIN), which inadvertently bypasses the critical `PARSE_BUF_SIZE` comparison. This bypass leads to an unchecked `memcpy()` operation, resulting in an out-of-bounds heap write. Successful exploitation allows for memory corruption, which can lead to application crashes (Denial of Service) or arbitrary code execution under the context of the user running the FFmpeg-based application. Defenders should prioritize patching all internal and third-party software leveraging FFmpeg libraries to version 9.0 or later.

## Impact

This vulnerability impacts any software suite or media processing pipeline that utilizes the affected versions of the FFmpeg library. Potential damage includes system compromise through arbitrary code execution or persistent service disruption via heap memory corruption. Given the prevalence of FFmpeg in media transcoders, video editors, and streaming servers, the scope of exposure is significant across multiple industry sectors.

## Recommendation

* Identify all internal and vendor-supplied software packages that bundle FFmpeg versions 0.5 through 8.9 for immediate remediation.
* Update all instances of FFmpeg to version 9.0 or later to address the vulnerability in `libavcodec/dvbsub_parser.c`.
* Audit ingestion pipelines that process WTV file formats to restrict untrusted input sources until patches are applied.
