---
brief_id: brief-2026-11-09-ffmpeg-vuln
event_id: brief-2026-11-09-ffmpeg-vuln
revision: 1
activity_at: "2026-11-09T19:56:11Z"
title: 'FFmpeg: Integer overflow in vulkan_decode.c (CVE-2026-125249)'
slug: 2026-11-ffmpeg-vuln
description: FFmpeg 7.1 through 9.0.2 contains an integer overflow in ff_vk_decode_add_slice() in libavcodec/vulkan_decode.c that miscalculates the Vulkan hwaccel bitstream buffer size.
date: "2026-11-09T19:56:11Z"
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
  - FFmpeg (7.1 through 9.0.2)
cves:
  - id: CVE-2026-125249
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125249
---

FFmpeg 7.1 through 9.0.2 contains an integer overflow in the `ff_vk_decode_add_slice()` function in `libavcodec/vulkan_decode.c`. This flaw causes a miscalculation of the Vulkan hwaccel bitstream buffer size. Attackers can supply a crafted stream with over 2 GiB of slice data per frame, causing `memcpy()` to write past a smaller pooled host-mapped buffer.
