---
title: Denial of Service Vulnerability in FFmpeg avpriv_h264_has_num_reorder_frames
slug: 2026-10-ffmpeg-null-ptr
description: A NULL pointer dereference vulnerability in FFmpeg version N-119856-gbe46370941 allows remote attackers to trigger a Denial of Service through specially crafted media files.
date: "2026-10-20T00:31:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:ffmpeg:ffmpeg:N-119856-gbe46370941:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - ffmpeg
vendors:
  - FFmpeg
products:
  - FFmpeg (N-119856-gbe46370941)
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-52290
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify and upgrade vulnerable FFmpeg binaries
      owner: IT Operations
      due: 72h
      evidence: CVE-2025-52290 disclosure
  mitigation_plan:
    - priority: immediate
      action: Upgrade FFmpeg to a version post N-119856-gbe46370941
      owner: IT Operations
      addresses: CVE-2025-52290
      evidence: NVD source
---

A NULL pointer dereference vulnerability, tracked as CVE-2025-52290, has been identified in the avpriv_h264_has_num_reorder_frames function of FFmpeg version N-119856-gbe46370941. This vulnerability occurs when the library processes a maliciously crafted media file containing invalid H.264 stream parameters. When the vulnerable function attempts to access the pointer, the dereference error causes an immediate application crash, leading to a Denial of Service. This impacts any application, service, or media processing pipeline that utilizes the affected FFmpeg build. Defenders should assess their software bill of materials (SBOM) to identify systems utilizing this specific version of FFmpeg and prioritize updating to a patched release.

## Impact

Successful exploitation leads to a crash of the service utilizing the library, resulting in a denial of service. The impact is significant for media streaming platforms, video transcoding services, and client-side applications that rely on FFmpeg for parsing untrusted video input, potentially leading to widespread service disruption.

## Recommendation

1. Inventory all production systems and applications that incorporate FFmpeg to identify instances of version N-119856-gbe46370941.
2. Upgrade the FFmpeg library to the latest stable release to remediate CVE-2025-52290.
3. Implement input validation and sandboxing for media processing pipelines to isolate parsing errors if immediate patching is not possible.
