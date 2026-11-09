---
brief_id: brief-2026-11-09-ffmpeg-integer-overflow
event_id: brief-2026-11-09-ffmpeg-integer-overflow
revision: 1
activity_at: "2026-11-09T19:55:21Z"
title: 'FFmpeg: Integer overflow in hap_parse_frame_header (CVE-2026-125222)'
slug: 2026-11-ffmpeg-integer-overflow
description: FFmpeg versions through 9.0.2 contain an integer overflow vulnerability in the hap_parse_frame_header function, which can be exploited by a crafted Hap video frame to cause a heap buffer overflow and potential remote code execution on 32-bit systems.
date: "2026-11-09T19:55:21Z"
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
    evidence: Attackers can craft Hap video frames with Snappy length prefixes that wrap tex_size, causing decompress_chunks_thread() to write outside tex_buf and crash the application or potentially execute code.
    confidence_band: high
cves:
  - id: CVE-2026-125222
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125222
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all applications, plugins, or services that depend on FFmpeg libraries to identify exposure of 32-bit builds.
      owner: IT Operations
      due: 72h
      evidence: Vulnerability affects FFmpeg through 9.0.2 in 32-bit builds.
  hunt_leads:
    - lead: Identify applications loading libavcodec libraries where the process is running as a 32-bit executable.
      technique_id: T1203
      data_needed:
        - Process architecture (32-bit vs 64-bit)
        - Loaded modules list
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is specific to 32-bit builds of FFmpeg.
  mitigation_plan:
    - priority: immediate
      action: Update FFmpeg to version > 9.0.2 when vendor releases patches or updates.
      owner: IT Operations
      addresses: CVE-2026-125222
      evidence: FFmpeg through 9.0.2 is vulnerable.
---

FFmpeg through version 9.0.2 is vulnerable to an integer overflow within the hap_parse_frame_header() function located in libavcodec/hapdec.c. This flaw occurs when processing maliciously crafted Hap video frames that contain Snappy length prefixes. On 32-bit builds, these prefixes can trigger an integer wrap-around on the tex_size variable, subsequently leading to a heap buffer overflow in decompress_chunks_thread(). An attacker could potentially leverage this condition to cause an application crash or achieve arbitrary code execution.

## Impact
Successful exploitation may result in an application crash (Denial of Service) or arbitrary code execution within the context of the user running the FFmpeg-dependent application. The vulnerability specifically impacts 32-bit environments.

## Recommendation
- Audit infrastructure to identify applications or services utilizing FFmpeg versions 9.0.2 or older.
- Prioritize patching or updating FFmpeg-dependent software to versions utilizing patched FFmpeg libraries once available from upstream or distribution maintainers.
- If immediate patching is not possible, implement strict input validation or sandboxing for untrusted video files processed by FFmpeg in 32-bit environments.
