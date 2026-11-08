---
brief_id: brief-2026-11-08-babeldoc-dos
event_id: brief-2026-11-08-babeldoc-dos
revision: 1
activity_at: "2026-11-08T17:30:49Z"
title: 'BabelDOC: Resource exhaustion vulnerability in PDF translation (CVE-2026-124553)'
slug: 2026-11-babeldoc-dos
description: BabelDOC versions 0.3.61 through 0.6.x are vulnerable to remote denial-of-service via crafted PDF documents containing malicious ToUnicode CMap spans that cause excessive CPU and memory consumption.
date: "2026-11-08T17:30:49Z"
type: advisory
types:
  - advisory
severities:
  - low
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
  - cpe:2.3:a:babeldoc:babeldoc:*:*:*:*:*:*:*:*
vendors:
  - BabelDOC
products:
  - BabelDOC (0.3.61 - 0.6.x)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can submit a crafted PDF whose embedded ToUnicode CMap declares a huge range, driving billions of loop iterations and stalling the translation worker.
    confidence_band: high
cves:
  - id: CVE-2026-124553
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124553
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade BabelDOC to version 0.7.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-124553 indicates a vulnerability in versions before 0.7.0
  hunt_leads:
    - lead: Identify abnormal CPU and memory utilization patterns in the BabelDOC translation service worker process.
      technique_id: T1499
      data_needed:
        - Process performance monitoring (CPU/Memory usage logs)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability leads to high CPU and memory consumption, stalling the worker.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 0.7.0
      owner: IT Operations
      addresses: CVE-2026-124553
      evidence: NVD disclosure
---

BabelDOC versions 0.3.61 to 0.6.x are susceptible to a resource exhaustion vulnerability (CVE-2026-124553). Remote attackers can trigger this condition by submitting a crafted PDF document with embedded ToUnicode CMaps containing unbounded `bfrange` and `cidrange` spans. Processing these spans forces the translation worker to perform billions of iterations, leading to high CPU usage, memory depletion, and denial of service.

## Impact

Successful exploitation results in a denial of service for the translation service by exhausting system resources (CPU and memory), rendering the application unresponsive to legitimate requests.

## Recommendation

Upgrade BabelDOC to version 0.7.0 or later immediately to include the patch addressing CMap iteration bounds. If patching is not immediately feasible, implement input validation or file size/complexity limits for PDF uploads to identify and reject documents containing oversized or abnormal CMap definitions before passing them to the translation worker.
