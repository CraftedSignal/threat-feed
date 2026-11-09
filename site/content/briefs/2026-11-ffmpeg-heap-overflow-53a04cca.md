---
brief_id: brief-2026-11-09-ffmpeg-heap-overflow-53a04cca
event_id: brief-2026-11-09-ffmpeg-heap-overflow-53a04cca
revision: 1
activity_at: "2026-11-09T19:55:50Z"
title: 'FFmpeg: Heap buffer overflow in ff_dxva2_hevc_fill_picture_parameters (CVE-2026-125239)'
slug: 2026-11-ffmpeg-heap-overflow-53a04cca
description: FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in ff_dxva2_hevc_fill_picture_parameters() that allows attackers to corrupt memory via crafted HEVC bitstreams during hardware-accelerated decoding on Windows.
date: "2026-11-09T19:55:50Z"
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
  - id: CVE-2026-125239
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125239
---

FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in the function `ff_dxva2_hevc_fill_picture_parameters()`. Attackers can supply crafted HEVC bitstreams with many non-uniformly spaced tiles to write controlled 16-bit values past fixed-size DXVA arrays. This issue occurs during DXVA2, D3D11VA, or D3D12VA decoding on Windows.
