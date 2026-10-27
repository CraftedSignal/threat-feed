---
brief_id: brief-2026-10-27-coregraphics-oob-write
event_id: brief-2026-10-27-coregraphics-oob-write
revision: 1
activity_at: "2026-10-27T12:49:06Z"
title: 'Apple iOS: CoreGraphics PDF stack out-of-bounds write vulnerabilities (CVE-2026-112611, CVE-2026-112610)'
slug: 2026-10-coregraphics-oob-write
description: Researchers have published analysis and crash-inducing proof-of-concept generators for two out-of-bounds write vulnerabilities in the Apple CoreGraphics PDF stack, both patched in iOS 27.2.
date: "2026-10-27T12:49:06Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified fix diff methodology provided in source.
cpes:
  - cpe:2.3:a:apple:ios:*:*:*:*:*:*:*:*
tags:
  - apple
  - ios
  - coregraphics
  - vulnerability
  - oob-write
vendors:
  - Apple
products:
  - iOS (<= 27.0)
affected_os:
  - iOS 27.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: 'The primary site was then proven on an owned, unpatched 27.0 device: a 7-line PDF crashes Preview deterministically.'
    confidence_band: high
cves:
  - id: CVE-2026-112610
    kev_status: "false"
  - id: CVE-2026-112611
    kev_status: "false"
references:
  - https://support.apple.com/en-us/149230
  - https://sploitus.com/exploit?id=E1FD2A00-1407-524F-855F-860D624C87B0
  - https://sploitus.com/exploit?id=E1FD2A00-1407-524F-855F-860D624C87B0&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch all iOS devices to version 27.2 or later.
      owner: IT Operations
      due: 48h
      evidence: Apple security advisory HT149230 confirms the fix for CVE-2026-112611 and CVE-2026-112610.
  hunt_leads:
    - lead: Search for unified logs indicating CoreGraphics shading errors
      technique_id: T1203
      data_needed:
        - Unified logs (log show)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: 'Unified log: CG-SEC-187882049: invalid function for type 5 shading.'
  mitigation_plan:
    - priority: immediate
      action: Enforce iOS 27.2 update across all managed mobile assets.
      owner: IT Operations
      addresses: CVE-2026-112611, CVE-2026-112610
      evidence: Source documentation for CVE-2026-112611 and CVE-2026-112610.
  gaps:
    - Limited visibility into historical exploitation prior to patch application.
---

Two out-of-bounds write vulnerabilities in the CoreGraphics PDF rendering stack were identified through function-level differential analysis of iOS 27.0 and 27.2 binaries. The vulnerabilities involve improper bounds checking during the processing of Type 5 (lattice-form Gouraud) shading (CVE-2026-112611) and CMap recursion (CVE-2026-112610). These flaws allow an attacker to write attacker-chosen values to out-of-bounds memory locations when a target application renders a maliciously crafted PDF. Apple addressed these issues in iOS 27.2.

## Impact
The vulnerabilities allow for the writing of arbitrary IEEE-754 double values to memory. While the published research and accompanying artifacts are restricted to crash-only oracles, the ability to perform out-of-bounds writes carries the potential for arbitrary code execution if chained with other primitives.

## Recommendation
- Update all iOS devices to iOS 27.2 (24B115) or later to mitigate the underlying vulnerabilities addressed in security advisory HT149230.
- Monitor for unauthorized or suspicious crash reports related to CoreGraphics or QuickLook processes using the provided crash-analysis methodology.
- Implement strict document handling policies for mobile devices, specifically limiting the automatic previewing or rendering of untrusted PDF files.
