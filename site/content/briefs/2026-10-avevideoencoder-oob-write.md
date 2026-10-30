---
brief_id: brief-2026-10-30-avevideoencoder-oob-write
event_id: brief-2026-10-30-avevideoencoder-oob-write
revision: 1
activity_at: "2026-10-30T09:39:42Z"
title: 'Apple AVEVideoEncoder: Out-of-bounds write (CVE-2026-112705)'
slug: 2026-10-avevideoencoder-oob-write
description: An out-of-bounds write vulnerability in Apple's AVEVideoEncoder component allows for kernel-level denials of service through specifically crafted high-resolution H.264 compression sessions.
date: "2026-10-30T09:39:42Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "1"
  rating: B1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: The vulnerability is documented by Apple (CVE-2026-112705); remediation requires OS updates.
cpes:
  - cpe:2.3:a:apple:avevideoencoder:*:*:*:*:*:*:*:*
tags:
  - apple
  - kernel
  - vulnerability
  - denial-of-service
  - cve-2026-112705
vendors:
  - Apple
products:
  - AVEVideoEncoder
affected_os:
  - iOS 26.0
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Apple describes CVE-2026-112705 as an AVEVideoEncoder out-of-bounds write that can cause unexpected system termination.
    confidence_band: high
cves:
  - id: CVE-2026-112705
    epss: 0.00237
    kev_status: "false"
references:
  - https://support.apple.com/en-us/149230
  - https://sploitus.com/exploit?id=8CC19184-A18A-5449-847B-F34679AF068F
  - https://sploitus.com/exploit?id=8CC19184-A18A-5449-847B-F34679AF068F&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch devices by updating to the latest Apple iOS versions as specified in the Apple security advisory.
      owner: IT Operations
      due: 48h
      evidence: Apple security advisory 149230
  hunt_leads:
    - lead: Identify devices running vulnerable iOS versions via MDM reporting to prioritize patching.
      technique_id: T1499
      data_needed:
        - MDM device inventory reports
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The advisory confirms the bug exists in specific Apple software versions.
  mitigation_plan:
    - priority: immediate
      action: Apply the latest iOS updates to address the out-of-bounds write in AVEVideoEncoder.
      owner: IT Operations
      addresses: CVE-2026-112705
      evidence: Apple support advisory
---

CVE-2026-112705 is an out-of-bounds write vulnerability within the AVEVideoEncoder component, which handles hardware-accelerated video compression on Apple devices. The vulnerability is triggered by specific H.264 `VTCompressionSession` configurations, specifically when using a 32768 x 16384 resolution with a BGRA pixel buffer. This action causes a kernel panic and subsequent device reboot. Apple has confirmed the issue and provided a fix via improved bounds checking in updated versions.

## Impact
The vulnerability results in an immediate denial-of-service condition, manifested as a kernel panic and device reboot. While the current public proof-of-concept is limited to a crash-only reproducer, out-of-bounds write vulnerabilities in kernel-mode components pose risks for memory corruption and potential privilege escalation in more sophisticated attack chains.

## Recommendation
- Update all affected Apple devices to the latest available software version to apply the security fix provided by Apple.
- Implement internal device management policies to enforce timely updates, particularly for mobile hardware (iPhone, iPad).
- Use mobile device management (MDM) telemetry to identify devices running outdated iOS versions.
