---
brief_id: brief-2026-11-09-ffmpeg-overflow
event_id: brief-2026-11-09-ffmpeg-overflow
revision: 1
activity_at: "2026-11-09T19:56:07Z"
title: 'FFmpeg: Integer overflow in Vulkan encoder (CVE-2026-125248)'
slug: 2026-11-ffmpeg-overflow
description: An integer overflow in the FFmpeg Vulkan encoder (libavcodec/ffv1enc_vulkan.c) allows remote attackers to cause memory corruption or application crashes through specially crafted high-resolution image or video files.
date: "2026-11-09T19:56:07Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified
cpes:
  - cpe:2.3:a:ffmpeg:ffmpeg:9.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ffmpeg:ffmpeg:9.0.1:*:*:*:*:*:*:*
  - cpe:2.3:a:ffmpeg:ffmpeg:9.0.2:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ffmpeg
  - memory-corruption
vendors:
  - FFmpeg
products:
  - FFmpeg (9.0 through 9.0.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply large GBRPF32 or GBRAPF32 images or videos that, when transcoded to FFV1 with the Vulkan encoder, trigger out-of-bounds GPU memory writes causing crashes or memory corruption.
    confidence_band: high
cves:
  - id: CVE-2026-125248
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125248
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify software dependencies using FFmpeg 9.x within the environment
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects FFmpeg 9.0 through 9.0.2
  hunt_leads:
    - lead: Monitor for application crashes or logs indicating GPU driver instability related to transcoding processes
      technique_id: T1203
      data_needed:
        - Application error logs
        - System event logs for GPU/Driver crashes
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability causes crashes or memory corruption via out-of-bounds GPU memory writes
  mitigation_plan:
    - priority: immediate
      action: Upgrade FFmpeg to a version outside of the affected 9.0-9.0.2 range
      owner: IT Operations
      addresses: CVE-2026-125248
      evidence: Vulnerability confirmed in FFmpeg 9.0-9.0.2
---

FFmpeg versions 9.0 through 9.0.2 contain an integer overflow vulnerability within `libavcodec/ffv1enc_vulkan.c`. The vulnerability manifests when the software attempts to allocate memory for the float remap GPU buffer. Supplying a large GBRPF32 or GBRAPF32 image or video for transcoding into the FFV1 format via the Vulkan encoder results in an undersized buffer allocation. This leads to an out-of-bounds GPU memory write, which can result in application crashes or memory corruption.

## Impact

Successful exploitation may result in a denial of service (application crash) or potential memory corruption on the host system running the transcoding process.

## Recommendation

* Inventory systems and applications utilizing FFmpeg libraries to identify exposure to versions 9.0 through 9.0.2.
* Update FFmpeg to a patched version once released by the vendor.
* Restrict the use of the Vulkan encoder in untrusted transcoding pipelines until the software is updated.
