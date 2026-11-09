---
brief_id: brief-2026-11-09-ffmpeg-vvc-overflow
event_id: brief-2026-11-09-ffmpeg-vvc-overflow
revision: 1
activity_at: "2026-11-09T19:56:24Z"
title: 'FFmpeg: VVC decoder heap-based memory corruption (CVE-2026-125251)'
slug: 2026-11-ffmpeg-vvc-overflow
description: FFmpeg through 9.0.2 contains an integer overflow vulnerability in the VVC decoder alloc_frame() function that leads to heap out-of-bounds writes on 32-bit builds.
date: "2026-11-09T19:56:24Z"
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
products:
  - FFmpeg (<= 9.0.2)
cves:
  - id: CVE-2026-125251
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125251
---

FFmpeg through 9.0.2 contains an integer overflow vulnerability in the VVC (H.266) decoder `alloc_frame()` function in `libavcodec/vvc/refs.c`. This flaw undersizes the reference picture list allocation on 32-bit builds. An attacker can provide a crafted VVC file with a large number of NAL units per access unit to trigger heap out-of-bounds writes and corrupt memory.
