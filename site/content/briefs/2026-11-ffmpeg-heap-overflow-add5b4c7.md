---
brief_id: brief-2026-11-09-ffmpeg-heap-overflow-add5b4c7
event_id: brief-2026-11-09-ffmpeg-heap-overflow-add5b4c7
revision: 1
activity_at: "2026-11-09T21:58:26Z"
title: 'FFmpeg: Heap buffer overflow in Huffyuv encoder (CVE-2026-125256)'
slug: 2026-11-ffmpeg-heap-overflow-add5b4c7
description: FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in ff_llvidenc_diff_bytes_rvv() that allows attackers to corrupt heap memory by triggering negative length values in the Huffyuv encoder.
date: "2026-11-09T21:58:26Z"
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
  - id: CVE-2026-125256
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125256
---

FFmpeg through 9.0.2 contains a heap buffer overflow vulnerability in the `ff_llvidenc_diff_bytes_rvv()` function. Attackers can supply RGB video narrower than 8 or 16 pixels for huffyuv transcoding on RVV-enabled RISC-V builds, causing writes past the encoder's temp buffer and resulting in heap memory corruption.
