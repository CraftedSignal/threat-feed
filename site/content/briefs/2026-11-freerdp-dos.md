---
brief_id: brief-2026-11-03-freerdp-dos
event_id: brief-2026-11-03-freerdp-dos
revision: 2
activity_at: "2026-11-04T16:51:33Z"
revision_history:
  - revision: 2
    at: "2026-11-04T16:51:33Z"
    checksum: sha256:f1b6531a3d88aad638847c1a31b02ed484dc679640b705910d7ba30d14f8a650
    summary: added coverage for FreeRDP (< 3.32.2)
    changed_fields:
      - action_plan
      - cves
      - lastmod
      - references
      - tags
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121951
title: 'FreeRDP: Denial of Service in WinPR via malformed clipboard images (CVE-2026-121386)'
slug: 2026-11-freerdp-dos
description: FreeRDP versions prior to 3.32.2 are susceptible to a denial of service vulnerability in WinPR due to missing error handling for libpng and libjpeg, which can be triggered by a malicious RDP server or a man-in-the-middle attacker providing malformed clipboard image payloads.
date: "2026-11-03T20:00:47Z"
lastmod: "2026-11-04T16:50:10Z"
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
tags:
  - denial-of-service
  - rdp
vendors:
  - FreeRDP
products:
  - FreeRDP (< 3.32.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote RDP client with an active session can send a truncated unknown input event to abort assertion-enabled server processes, causing denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-121386
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-121951
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121386
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121951
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
    - lead: Monitor for abnormal service crashes or frequent restarts of the FreeRDP server service.
      technique_id: T1499
      data_needed:
        - Application crash logs (e.g., Windows Event Logs, Syslog, or service manager logs)
      priority: medium
      confidence: medium
      disposition: monitor-only
      evidence: A remote RDP client with an active session can send a truncated unknown input event to abort assertion-enabled server processes.
  mitigation_plan:
    - priority: immediate
      action: Upgrade FreeRDP to version 3.32.2 or later
      owner: IT Operations
      addresses: CVE-2026-121386
      evidence: FreeRDP before 3.32.2 contains a denial of service vulnerability in WinPR
    - priority: immediate
      action: Upgrade FreeRDP to version 3.32.2 or later.
      owner: IT Operations
      addresses: CVE-2026-121951
      evidence: FreeRDP 3.0.0 before 3.32.2 server-side RDP peer input parsing skips the six-byte body of a slow-path input event.
updates:
  - at: "2026-11-04T16:50:10Z"
    level: L2
    summary: added coverage for FreeRDP (< 3.32.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-121951
---

FreeRDP versions before 3.32.2 contain a denial of service vulnerability located in the WinPR library's `winpr_read_png_from_buffer()` and `winpr_convert_from_jpeg()` functions. The vulnerability stems from insufficient error handling when interacting with the `libpng` and `libjpeg` libraries. An attacker acting as a malicious RDP server or performing a man-in-the-middle (MITM) attack can trigger this flaw by providing a malformed PNG or a truncated JPEG payload via the RDP clipboard channel. Successful exploitation causes the FreeRDP client process to abort or terminate unexpectedly.

## Impact

The vulnerability allows an unauthenticated remote attacker to cause a denial of service by crashing the client application. No code execution is documented as part of this vulnerability.

## Recommendation

Update all instances of the FreeRDP client to version 3.32.2 or later immediately to incorporate the required error handling for image processing functions.
