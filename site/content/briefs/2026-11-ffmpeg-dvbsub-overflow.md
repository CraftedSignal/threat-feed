---
brief_id: brief-2026-11-09-ffmpeg-dvbsub-overflow
event_id: brief-2026-11-09-ffmpeg-dvbsub-overflow
revision: 1
activity_at: "2026-11-09T19:55:37Z"
title: 'FFmpeg: Heap buffer overflow in dvbsub_encode (CVE-2026-125233)'
slug: 2026-11-ffmpeg-dvbsub-overflow
description: FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in dvbsub_encode() in libavcodec/dvbsubenc.c due to undercounting CLUT segment headers.
date: "2026-11-09T19:55:37Z"
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
  - id: CVE-2026-125233
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125233
---

FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in `dvbsub_encode()` in `libavcodec/dvbsubenc.c`. The vulnerability occurs because the code undercounts each CLUT segment header by two bytes. 

## Impact
Attackers can supply a file with many bitmap subtitle rectangles that, when transcoded to the dvbsub encoder, writes past the output buffer and corrupts heap memory.
