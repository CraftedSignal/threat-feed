---
brief_id: brief-2026-11-09-ffmpeg-heap-overflow-e749998b
event_id: brief-2026-11-09-ffmpeg-heap-overflow-e749998b
revision: 1
activity_at: "2026-11-09T19:53:02Z"
title: 'FFmpeg: PSD decoder heap buffer overflow (CVE-2026-125213)'
slug: 2026-11-ffmpeg-heap-overflow-e749998b
description: FFmpeg versions through 9.0.2 are vulnerable to a heap buffer overflow in the PSD decoder, allowing remote attackers to achieve memory corruption or arbitrary code execution via crafted PSD images on 32-bit systems.
date: "2026-11-09T19:53:02Z"
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
  validation_status: Needs environment validation to confirm 32-bit build dependencies
cpes:
  - cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*
vendors:
  - FFmpeg
products:
  - FFmpeg (<= 9.0.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can choose dimensions and channel counts whose product exceeds 4 GB, truncating the av_malloc allocation size so decode_rle() writes attacker-controlled data past the buffer, causing crashes or possible code execution.
    confidence_band: high
cves:
  - id: CVE-2026-125213
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125213
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify applications in the environment using 32-bit FFmpeg libraries.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability specifically affects 32-bit builds due to integer truncation.
  hunt_leads:
    - lead: Monitor for application crashes involving ffmpeg processes or libraries when handling image files.
      technique_id: T1203
      data_needed:
        - Application crash logs
        - Process memory dumps
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: The flaw causes crashes when an attacker provides a crafted PSD image.
  mitigation_plan:
    - priority: immediate
      action: Upgrade FFmpeg to a patched version beyond 9.0.2.
      owner: IT Operations
      addresses: CVE-2026-125213
      evidence: Vulnerability exists in FFmpeg through 9.0.2.
---

FFmpeg versions through 9.0.2 contain a heap buffer overflow vulnerability in the PSD decoder located in 'libavcodec/psd.c'. The issue occurs due to improper handling of image dimensions and channel counts on 32-bit builds, where the product of these values can exceed 4 GB. This triggers an integer truncation during the 'av_malloc' allocation, subsequently allowing 'decode_rle()' to write data beyond the allocated heap buffer boundaries.

## Impact

Successful exploitation may result in process crashes (denial of service) or potential arbitrary code execution under the context of the application utilizing the FFmpeg library.

## Recommendation

- Upgrade FFmpeg to a version beyond 9.0.2 as soon as a patch is available.
- Implement memory safety monitoring for applications using FFmpeg to process untrusted PSD files.
- Audit infrastructure to identify applications utilizing 32-bit builds of the FFmpeg library.
