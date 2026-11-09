---
brief_id: brief-2026-11-09-ffmpeg-buffer-overflow-3150fe62
event_id: brief-2026-11-09-ffmpeg-buffer-overflow-3150fe62
revision: 1
activity_at: "2026-11-09T19:55:15Z"
title: 'FFmpeg: Heap buffer overflow in vdpau_hevc_start_frame (CVE-2026-125219)'
slug: 2026-11-ffmpeg-buffer-overflow-3150fe62
description: FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in vdpau_hevc_start_frame() within libavcodec/vdpau_hevc.c.
date: "2026-11-09T19:55:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
  - id: CVE-2026-125219
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125219
---

FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in vdpau_hevc_start_frame() in libavcodec/vdpau_hevc.c that copies unbounded PPS tile counts into fixed-size VDPAU arrays. Attackers can supply crafted HEVC bitstreams with excessive tile columns or rows to write controlled 16-bit values past heap-allocated hwaccel data, corrupting memory in applications using VDPAU decoding.
