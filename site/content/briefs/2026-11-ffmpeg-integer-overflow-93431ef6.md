---
brief_id: brief-2026-11-09-ffmpeg-integer-overflow-93431ef6
event_id: brief-2026-11-09-ffmpeg-integer-overflow-93431ef6
revision: 1
activity_at: "2026-11-09T19:55:27Z"
title: 'FFmpeg: Integer overflow in cbs_jpeg_write_scan (CVE-2026-125227)'
slug: 2026-11-ffmpeg-integer-overflow-93431ef6
description: FFmpeg versions through 9.0.2 contain an integer overflow in the cbs_jpeg_write_scan function, leading to heap buffer overflows on 32-bit architectures when processing crafted MJPEG/JPEG streams.
date: "2026-11-09T19:55:27Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ffmpeg
  - memory-corruption
vendors:
  - FFmpeg
products:
  - FFmpeg (<= 9.0.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply a crafted MJPEG/JPEG stream... to corrupt the heap or crash the application.
    confidence_band: high
cves:
  - id: CVE-2026-125227
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125227
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify and inventory all 32-bit FFmpeg deployments within the environment
      owner: IT Operations
      due: 72h
      evidence: Vulnerability impacts heap buffer overflow on 32-bit builds only.
  hunt_leads:
    - lead: Identify applications performing intensive video processing or stream decoding using 32-bit libraries
      technique_id: T1203
      data_needed:
        - Application crash logs
        - Library dependency inventory
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation involves processing MJPEG/JPEG streams via CBS bitstream filters.
  mitigation_plan:
    - priority: medium
      action: Upgrade affected FFmpeg installations to a version where this integer overflow is resolved
      owner: IT Operations
      addresses: CVE-2026-125227
      evidence: FFmpeg through 9.0.2 contains an integer overflow in cbs_jpeg_write_scan().
---

FFmpeg through 9.0.2 contains an integer overflow in the cbs_jpeg_write_scan() function located in libavcodec/cbs_jpeg.c. This vulnerability is specifically triggered on 32-bit architectures when the application processes a crafted MJPEG or JPEG stream containing a scan size of 512 MiB or greater, handled by CBS bitstream filters such as filter_units. Exploitation results in heap buffer corruption or application crashes.

## Impact

Successful exploitation may lead to a denial of service (application crash) or potential memory corruption via heap buffer overflow. Impact is limited to 32-bit build environments.

## Recommendation

* Inventory systems and applications utilizing FFmpeg versions 9.0.2 or earlier.
* Prioritize migration from 32-bit to 64-bit builds of FFmpeg where possible, as the overflow condition is specific to 32-bit architectures.
* Monitor for security updates from FFmpeg and apply patches once a version addressing CVE-2026-125227 is released.
