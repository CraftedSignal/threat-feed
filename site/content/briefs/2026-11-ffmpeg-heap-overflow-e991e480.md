---
brief_id: brief-2026-11-09-ffmpeg-heap-overflow-e991e480
event_id: brief-2026-11-09-ffmpeg-heap-overflow-e991e480
revision: 1
activity_at: "2026-11-09T23:59:00Z"
title: 'FFmpeg: Heap overflow in libavcodec/qsvenc.c (CVE-2026-125235)'
slug: 2026-11-ffmpeg-heap-overflow-e991e480
description: FFmpeg through 9.0.2 contains a heap overflow vulnerability in libavcodec/qsvenc.c caused by the reuse of an undersized pooled QSVFrame buffer when input dimensions increase mid-stream without rescaling, which can lead to application crashes or heap memory corruption.
date: "2026-11-09T23:59:00Z"
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
  - FFmpeg (through 9.0.2)
cves:
  - id: CVE-2026-125235
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125235
---

FFmpeg through 9.0.2 contains a heap overflow vulnerability in libavcodec/qsvenc.c. Attackers can supply crafted input that increases in resolution mid-stream, which, when transcoded with Intel Quick Sync encoders without rescaling, causes the application to reuse an undersized pooled QSVFrame buffer. This results in heap memory corruption or application crashes.
