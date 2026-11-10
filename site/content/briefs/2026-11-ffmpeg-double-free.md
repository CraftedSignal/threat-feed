---
brief_id: brief-2026-11-09-ffmpeg-double-free
event_id: brief-2026-11-09-ffmpeg-double-free
revision: 1
activity_at: "2026-11-09T23:59:35Z"
title: 'FFmpeg: Heap memory corruption via double free vulnerability (CVE-2026-125269)'
slug: 2026-11-ffmpeg-double-free
description: FFmpeg through 9.0.2 contains a double free vulnerability in libavcodec/cbs_sei.c that allows heap memory corruption via crafted H.264 streams.
date: "2026-11-09T23:59:35Z"
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
cpes:
  - cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*
vendors:
  - FFmpeg
products:
  - FFmpeg (through 9.0.2)
cves:
  - id: CVE-2026-125269
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125269
---

FFmpeg through 9.0.2 contains a double free vulnerability in libavcodec/cbs_sei.c where cbs_sei_delete_message() leaves a stale extension_data reference that ff_cbs_sei_add_message() reuses. Attackers can supply a crafted H.264 stream with a display orientation SEI message followed by payload extension data, processed by h264_metadata with display_orientation=insert, to corrupt heap memory.
