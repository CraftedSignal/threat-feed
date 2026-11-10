---
brief_id: brief-2026-11-09-ffmpeg-integer-overflow-d0e0d71a
event_id: brief-2026-11-09-ffmpeg-integer-overflow-d0e0d71a
revision: 1
activity_at: "2026-11-09T23:59:17Z"
title: 'FFmpeg: Integer overflow in ff_prores_kostya_encode_init (CVE-2026-125259)'
slug: 2026-11-ffmpeg-integer-overflow-d0e0d71a
description: FFmpeg through 9.0.2 contains an integer overflow vulnerability in ff_prores_kostya_encode_init() due to 32-bit arithmetic miscalculating frame_size_upper_bound for large frame dimensions.
date: "2026-11-09T23:59:17Z"
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
  - id: CVE-2026-125259
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125259
---

FFmpeg through 9.0.2 contains an integer overflow vulnerability in the ff_prores_kostya_encode_init() function caused by 32-bit arithmetic miscalculating frame_size_upper_bound for large frame dimensions. Attackers can supply a high-resolution video transcoded with the prores_ks encoder, which causes encode_frame() to write slices past an undersized packet buffer, leading to heap memory corruption.
