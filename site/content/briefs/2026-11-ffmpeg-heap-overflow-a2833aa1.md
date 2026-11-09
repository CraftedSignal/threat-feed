---
brief_id: brief-2026-11-09-ffmpeg-heap-overflow-a2833aa1
event_id: brief-2026-11-09-ffmpeg-heap-overflow-a2833aa1
revision: 1
activity_at: "2026-11-09T19:52:20Z"
title: 'FFmpeg: Heap buffer overflow in Cook multichannel decoder (CVE-2026-125203)'
slug: 2026-11-ffmpeg-heap-overflow-a2833aa1
description: A heap buffer overflow in the FFmpeg Cook multichannel decoder allows an out-of-bounds write via a crafted RealMedia stream.
date: "2026-11-09T19:52:20Z"
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
  - FFmpeg (< 8.1.3)
  - FFmpeg (9.x < 9.0.2)
cves:
  - id: CVE-2026-125203
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125203
---

FFmpeg versions before 8.1.3 and 9.x before 9.0.2 contain a heap buffer overflow vulnerability in the Cook multichannel decoder located in 'libavcodec/cook.c'. The vulnerability occurs because the decoder fails to verify that subpacket channel masks are disjoint. An attacker can supply a crafted RealMedia Cook stream with overlapping subpacket masks, causing the 'cook_decode_frame()' function to write decoded samples beyond allocated output planes in any application decoding the file.
