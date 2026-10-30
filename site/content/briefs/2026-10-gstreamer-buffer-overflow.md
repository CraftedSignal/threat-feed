---
brief_id: brief-2026-10-30-gstreamer-buffer-overflow
event_id: brief-2026-10-30-gstreamer-buffer-overflow
revision: 1
activity_at: "2026-10-30T19:36:47Z"
title: 'GStreamer gst-plugins-bad: Integer overflow in H.266/VVC parser (CVE-2026-119777)'
slug: 2026-10-gstreamer-buffer-overflow
description: An integer overflow vulnerability in GStreamer's gst-plugins-bad H.266/VVC parser can lead to stack-based buffer overflows and potential arbitrary code execution when processing malformed media.
date: "2026-10-30T19:36:47Z"
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
  validation_status: Awaiting patch release from upstream
cpes:
  - cpe:2.3:a:gstreamer:gst-plugins-bad:*:*:*:*:*:*:*:*
vendors:
  - GStreamer
products:
  - gst-plugins-bad
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker could cause an application to crash and may be able to execute code in the context of the affected application.
    confidence_band: high
cves:
  - id: CVE-2026-119777
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119777
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory systems and applications leveraging GStreamer and gst-plugins-bad
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-119777
  hunt_leads:
    - lead: Identify applications invoking GStreamer binary modules
      technique_id: T1203
      data_needed:
        - Process command line and loaded module paths
      priority: medium
      confidence: medium
      disposition: defer
      evidence: Vulnerability exists within gst-plugins-bad parser
  mitigation_plan:
    - priority: immediate
      action: Monitor GStreamer repository for patched releases of gst-plugins-bad
      owner: Security Engineering
      addresses: CVE-2026-119777
      evidence: CVE-2026-119777
---

A vulnerability exists in the GStreamer gst-plugins-bad component within the H.266/VVC parser (CVE-2026-119777). An integer overflow occurs when the parser processes the profile, tier, and level fields of a malformed H.266 media file or stream. This overflow results in a stack-based buffer overflow, which can lead to application crashes or arbitrary code execution in the context of the process handling the media.

## Impact
Successful exploitation allows for an application crash (Denial of Service) or potential arbitrary code execution within the security context of the affected application process.

## Recommendation
Inventory all applications utilizing the GStreamer framework and specifically the gst-plugins-bad component. Monitor official GStreamer project security advisories for patch availability and upgrade immediately upon release.
