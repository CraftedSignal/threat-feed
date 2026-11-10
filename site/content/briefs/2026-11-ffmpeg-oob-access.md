---
brief_id: brief-2026-11-10-ffmpeg-oob-access
event_id: brief-2026-11-10-ffmpeg-oob-access
revision: 1
activity_at: "2026-11-10T02:01:38Z"
title: 'FFmpeg: Out-of-bounds memory access in huffyuvenc (CVE-2026-125229)'
slug: 2026-11-ffmpeg-oob-access
description: FFmpeg versions through 9.0.2 contain an out-of-bounds memory access vulnerability in the encode_frame function that can be triggered by processing malformed video frames, potentially resulting in application crashes or memory corruption.
date: "2026-11-10T02:01:38Z"
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
  validation_status: needs_environment_validation
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
    evidence: Attackers can supply a tiny video... that causes... out-of-bounds reads and writes when transcoded to huffyuv or ffvhuff, crashing the encoder.
    confidence_band: high
cves:
  - id: CVE-2026-125229
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125229
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all software deployments that include FFmpeg binary or shared libraries
      owner: IT Operations
      due: 48h
      evidence: FFmpeg through 9.0.2 contains an out-of-bounds memory access vulnerability
  hunt_leads:
    - lead: Identify processes utilizing ffmpeg that terminate unexpectedly when processing untrusted video files
      technique_id: T1203
      data_needed:
        - OS application crash logs (e.g., Windows Event ID 1000, Linux auditd/syslog for segfaults)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can supply a tiny video... that causes... out-of-bounds reads and writes when transcoded to huffyuv or ffvhuff, crashing the encoder.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches or update to the latest version of FFmpeg as soon as released
      owner: IT Operations
      addresses: CVE-2026-125229
      evidence: FFmpeg through 9.0.2 contains an out-of-bounds memory access vulnerability
---

FFmpeg through version 9.0.2 contains an out-of-bounds memory access vulnerability in the `encode_frame()` function within `libavcodec/huffyuvenc.c`. The vulnerability exists because `encode_init()` fails to validate minimum frame dimensions when using the median predictor. An attacker can supply a specially crafted video file with undersized dimensions, such as frames that are 2 pixels wide or 1 to 2 pixels tall, which triggers negative `sub_median_pred` lengths and subsequent out-of-bounds memory operations during transcoding to huffyuv or ffvhuff.

## Impact

Successful exploitation may result in an application crash, causing a denial of service for any process utilizing the vulnerable FFmpeg library for video transcoding. The nature of the out-of-bounds read and write operations also presents a risk of memory corruption.

## Recommendation

- Audit systems for applications that utilize the FFmpeg library for video transcoding, particularly those that accept user-provided video files.
- Monitor for and apply updates to FFmpeg once a security patch addressing CVE-2026-125229 is released by the maintainers.
- Implement input validation on applications using FFmpeg to reject video files with dimensions below standard expected thresholds until the library can be updated.
