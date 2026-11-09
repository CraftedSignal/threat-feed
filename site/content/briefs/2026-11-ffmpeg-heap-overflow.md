---
brief_id: brief-2026-11-09-ffmpeg-heap-overflow
event_id: brief-2026-11-09-ffmpeg-heap-overflow
revision: 1
activity_at: "2026-11-09T19:52:02Z"
title: 'FFmpeg: Heap buffer overflow in liboapve_encode (CVE-2026-125196)'
slug: 2026-11-ffmpeg-heap-overflow
description: A heap buffer overflow in FFmpeg through 9.0.2 allows for heap memory corruption when transcoding video files with mid-stream resolution changes.
date: "2026-11-09T19:52:02Z"
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
  - id: CVE-2026-125196
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125196
---

FFmpeg versions through 9.0.2 contain a heap buffer overflow vulnerability in the `liboapve_encode()` function located in `libavcodec/liboapvenc.c`. The vulnerability is triggered when processing frames larger than the configured encoder dimensions. Attackers can craft video files with mid-stream resolution changes so that transcoding to APV without rescaling writes pixel data past the `imgb` plane buffers, resulting in heap memory corruption.
