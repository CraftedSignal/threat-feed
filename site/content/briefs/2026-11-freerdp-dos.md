---
brief_id: brief-2026-11-03-freerdp-dos
event_id: brief-2026-11-03-freerdp-dos
revision: 1
activity_at: "2026-11-03T20:00:47Z"
title: 'FreeRDP: Denial of Service in WinPR via malformed clipboard images (CVE-2026-121386)'
slug: 2026-11-freerdp-dos
description: FreeRDP versions prior to 3.32.2 are susceptible to a denial of service vulnerability in WinPR due to missing error handling for libpng and libjpeg, which can be triggered by a malicious RDP server or a man-in-the-middle attacker providing malformed clipboard image payloads.
date: "2026-11-03T20:00:47Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Patch management verification pending
cpes:
  - cpe:2.3:a:freerdp:freerdp:*:*:*:*:*:*:*:*
vendors:
  - FreeRDP
products:
  - FreeRDP (< 3.32.2)
cves:
  - id: CVE-2026-121386
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121386
action_plan:
  priority: elevated
  owners:
    - IT Operations
  hunt_leads:
    - lead: Identify endpoints running vulnerable FreeRDP versions
      data_needed:
        - Software inventory logs
        - Endpoint management telemetry
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: FreeRDP before 3.32.2 contains a denial of service vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade FreeRDP to version 3.32.2 or later
      owner: IT Operations
      addresses: CVE-2026-121386
      evidence: FreeRDP before 3.32.2 contains a denial of service vulnerability in WinPR
---

FreeRDP versions before 3.32.2 contain a denial of service vulnerability located in the WinPR library's `winpr_read_png_from_buffer()` and `winpr_convert_from_jpeg()` functions. The vulnerability stems from insufficient error handling when interacting with the `libpng` and `libjpeg` libraries. An attacker acting as a malicious RDP server or performing a man-in-the-middle (MITM) attack can trigger this flaw by providing a malformed PNG or a truncated JPEG payload via the RDP clipboard channel. Successful exploitation causes the FreeRDP client process to abort or terminate unexpectedly.

## Impact

The vulnerability allows an unauthenticated remote attacker to cause a denial of service by crashing the client application. No code execution is documented as part of this vulnerability.

## Recommendation

Update all instances of the FreeRDP client to version 3.32.2 or later immediately to incorporate the required error handling for image processing functions.
