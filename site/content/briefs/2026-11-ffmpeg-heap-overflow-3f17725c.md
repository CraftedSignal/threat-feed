---
brief_id: brief-2026-11-09-ffmpeg-heap-overflow-3f17725c
event_id: brief-2026-11-09-ffmpeg-heap-overflow-3f17725c
revision: 1
activity_at: "2026-11-09T21:58:44Z"
title: 'FFmpeg: Heap buffer overflow in libavcodec (CVE-2026-125260)'
slug: 2026-11-ffmpeg-heap-overflow-3f17725c
description: FFmpeg versions through 9.0.2 are vulnerable to a heap buffer overflow in libavcodec/exrenc.c that can cause memory corruption and application crashes during OpenEXR RLE encoding of frames exceeding initial height.
date: "2026-11-09T21:58:44Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation of library inventory.
cpes:
  - cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*
vendors:
  - FFmpeg
products:
  - FFmpeg (<= 9.0.2)
cves:
  - id: CVE-2026-125260
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125260
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory applications using FFmpeg library versions 9.0.2 or earlier
      owner: IT Operations
      due: 48h
      evidence: FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability
  hunt_leads:
    - lead: Hunt for application crashes involving processes that link against libavcodec
      data_needed:
        - System error logs
        - Application crash dumps
        - Process exit codes
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can supply crafted input... to write pointers past the scanline array and crash the application
  mitigation_plan:
    - priority: immediate
      action: Upgrade FFmpeg to the latest patched version when available
      owner: IT Operations
      addresses: CVE-2026-125260
      evidence: FFmpeg through 9.0.2 contains a heap buffer overflow
---

FFmpeg versions 9.0.2 and earlier contain a heap buffer overflow vulnerability in the file libavcodec/exrenc.c. The flaw resides in the encode_scanline_rle() function. An attacker can trigger this vulnerability by providing a crafted input file that, when transcoded to OpenEXR with RLE compression, contains frame dimensions that exceed the encoder's initially configured height. This condition leads to an out-of-bounds write beyond the scanline array, resulting in heap memory corruption and application crashes.

## Impact

The vulnerability allows an attacker to cause an application crash. While the source confirms heap memory corruption, it does not explicitly confirm remote code execution (RCE). The impact is primarily denial of service for any application utilizing FFmpeg to transcode media inputs.

## Recommendation

- Identify all systems and applications within the environment that utilize FFmpeg libraries.
- Prioritize patching FFmpeg to a version beyond 9.0.2 once a secure version is made available by the maintainers.
- Implement sandboxing or isolation for media processing services that handle untrusted, user-supplied files to contain potential crashes and exploitation attempts.
