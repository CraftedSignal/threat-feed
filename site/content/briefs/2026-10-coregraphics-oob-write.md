---
brief_id: brief-2026-10-27-coregraphics-oob-write
event_id: brief-2026-10-27-coregraphics-oob-write
revision: 2
activity_at: "2026-10-27T23:47:03Z"
revision_history:
  - revision: 2
    at: "2026-10-27T23:47:03Z"
    checksum: sha256:a425c37845f99a561377e652f7221813a417b269561b6d703caf6e1cd83f4ef2
    summary: severity → critical; added CVE-2026-112427 +3; OS ios; OS ipados; OS macos; OS tvos; OS watchos; OS visionos
    changed_fields:
      - action_plan
      - affected_os
      - affected_products
      - cpes
      - cves
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - severity
      - tags
      - ttps
      - updates
    source_urls:
      - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-121
title: 'Apple iOS: CoreGraphics PDF stack out-of-bounds write vulnerabilities (CVE-2026-112611, CVE-2026-112610)'
slug: 2026-10-coregraphics-oob-write
description: Researchers have published analysis and crash-inducing proof-of-concept generators for two out-of-bounds write vulnerabilities in the Apple CoreGraphics PDF stack, both patched in iOS 27.2.
date: "2026-10-27T12:49:06Z"
lastmod: "2026-10-27T23:46:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*
tags:
  - apple
  - ios
  - coregraphics
  - vulnerability
  - oob-write
  - rce
  - privilege-escalation
  - macos
vendors:
  - Apple
products:
  - iOS (<= 27.0)
  - iOS (< 27.2, 26 < 26.7.2, 18 < 18.7.11)
  - iPadOS (< 27.2, 26 < 26.7.2, 18 < 18.7.11)
  - macOS Golden Gate (< 27.2)
  - macOS Tahoe (< 26.7.2)
  - macOS Sequoia (< 15.8.2)
  - tvOS (< 27.2)
  - watchOS (< 27.2)
  - visionOS (< 27.2)
  - Safari (< 27.2)
affected_os:
  - iOS 27.0
  - iOS
  - iPadOS
  - macOS
  - tvOS
  - watchOS
  - visionOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: 'The primary site was then proven on an owned, unpatched 27.0 device: a 7-line PDF crashes Preview deterministically.'
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: a remote attacker may be able to cause arbitrary code execution due to an authentication issue (CVE-2026-112427; macOS Golden Gate).
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: an unprivileged attacker may be able to execute arbitrary code as root (CVE-2026-112438); an app may be able to execute arbitrary code with kernel privileges (CVE-2026-86916; macOS Tahoe).
    confidence_band: high
cves:
  - id: CVE-2026-112610
    kev_status: "false"
  - id: CVE-2026-112611
    kev_status: "false"
  - id: CVE-2026-112427
    kev_status: unknown
  - id: CVE-2026-112438
    kev_status: unknown
  - id: CVE-2026-86916
    kev_status: unknown
  - id: CVE-2026-86950
    cvss: 8.8
    epss: 0.26166
    kev_status: "false"
references:
  - https://support.apple.com/en-us/149230
  - https://sploitus.com/exploit?id=E1FD2A00-1407-524F-855F-860D624C87B0
  - https://sploitus.com/exploit?id=E1FD2A00-1407-524F-855F-860D624C87B0&utm_source=rss&utm_medium=rss
  - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-121
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
    - SOC
  immediate_actions:
    - action: Patch all iOS devices to version 27.2 or later.
      owner: IT Operations
      due: 48h
      evidence: Apple security advisory HT149230 confirms the fix for CVE-2026-112611 and CVE-2026-112610.
    - action: Patch all Apple assets to the latest available versions addressing the listed CVEs.
      owner: IT Operations
      due: 24h
      evidence: Systems Affected list provided in advisory
  hunt_leads:
    - lead: Search for unified logs indicating CoreGraphics shading errors
      technique_id: T1203
      data_needed:
        - Unified logs (log show)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: 'Unified log: CG-SEC-187882049: invalid function for type 5 shading.'
    - lead: Hunt for evidence of exploitation of CVE-2026-86950 by identifying anomalous process execution or crashes associated with CoreGraphics-related processes.
      technique_id: T1203
      data_needed:
        - Crash logs (macOS/iOS)
        - Endpoint telemetry showing suspicious process spawns from image processing services
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-86950 is noted as being actively exploited in the wild.
  mitigation_plan:
    - priority: immediate
      action: Enforce iOS 27.2 update across all managed mobile assets.
      owner: IT Operations
      addresses: CVE-2026-112611, CVE-2026-112610
      evidence: Source documentation for CVE-2026-112611 and CVE-2026-112610.
    - priority: immediate
      action: Upgrade macOS, iOS, iPadOS, tvOS, watchOS, and visionOS to the specified secure versions.
      owner: IT Operations
      addresses: All listed CVEs including CVE-2026-86950
      evidence: Systems Affected and Technical Summary sections
  gaps:
    - Limited visibility into historical exploitation prior to patch application.
updates:
  - at: "2026-10-27T23:46:03Z"
    level: L3
    summary: severity → critical; added CVE-2026-112427 +3; OS ios; OS ipados; OS macos; OS tvos; OS watchos; OS visionos
    sources:
      - ms-isac
    source_urls:
      - https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-apple-products-could-allow-for-arbitrary-code-execution_2026-121
---

Two out-of-bounds write vulnerabilities in the CoreGraphics PDF rendering stack were identified through function-level differential analysis of iOS 27.0 and 27.2 binaries. The vulnerabilities involve improper bounds checking during the processing of Type 5 (lattice-form Gouraud) shading (CVE-2026-112611) and CMap recursion (CVE-2026-112610). These flaws allow an attacker to write attacker-chosen values to out-of-bounds memory locations when a target application renders a maliciously crafted PDF. Apple addressed these issues in iOS 27.2.

## Impact
The vulnerabilities allow for the writing of arbitrary IEEE-754 double values to memory. While the published research and accompanying artifacts are restricted to crash-only oracles, the ability to perform out-of-bounds writes carries the potential for arbitrary code execution if chained with other primitives.

## Recommendation
- Update all iOS devices to iOS 27.2 (24B115) or later to mitigate the underlying vulnerabilities addressed in security advisory HT149230.
- Monitor for unauthorized or suspicious crash reports related to CoreGraphics or QuickLook processes using the provided crash-analysis methodology.
- Implement strict document handling policies for mobile devices, specifically limiting the automatic previewing or rendering of untrusted PDF files.
