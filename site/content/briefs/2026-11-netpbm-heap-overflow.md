---
brief_id: brief-2026-11-02-netpbm-heap-overflow
event_id: brief-2026-11-02-netpbm-heap-overflow
revision: 1
activity_at: "2026-11-02T15:48:38Z"
title: 'Netpbm: Heap-based buffer overflow in sgitopnm (CVE-2026-120431)'
slug: 2026-11-netpbm-heap-overflow
description: Netpbm is vulnerable to a heap-based buffer overflow in the sgitopnm utility via crafted SGI image files, potentially allowing for arbitrary code execution.
date: "2026-11-02T15:48:38Z"
lastmod: "2026-11-02T15:48:54Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Standard vulnerability brief based on NVD data.
cpes:
  - cpe:2.3:a:netpbm:netpbm:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - buffer-overflow
vendors:
  - Netpbm
products:
  - Netpbm (< 10.86.51, 11.x < 11.02.29, 11.03 < 11.15.07)
  - Netpbm (< 10.86.51, < 11.02.30, < 11.15.08)
  - Netpbm (< 10.86.51, 11.02.30, 11.15.08)
  - Netpbm (< 10.86.51, 11.x < 11.02.30, 11.03 < 11.15.08)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply crafted SGI files with oversized offset table lengths to write controlled data past the heap buffer, causing crashes or potential code execution.
    confidence_band: high
cves:
  - id: CVE-2026-120431
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-120432
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-120433
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-120434
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120431
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120432
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120433
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120434
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Netpbm to 10.86.51, 11.02.29, 11.15.07 or later
      owner: IT Operations
      due: 7d
      evidence: CVE-2026-120431 advisory remediation requirement
  hunt_leads:
    - lead: Identify processes executing sgitopnm with RLE-compressed SGI image inputs
      technique_id: T1203
      data_needed:
        - Process command line arguments for sgitopnm
        - File access logs indicating processed .sgi or .rgb files
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is triggered specifically by the sgitopnm utility processing crafted files
    - lead: Identify systems utilizing winicontopam on untrusted input
      technique_id: T1203
      data_needed:
        - Process execution logs
        - Application logs showing image processing events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: winicontopam is the vulnerable component requiring input file processing.
    - lead: Search for the usage of the 'picttoppm' binary in system process logs to identify servers or applications utilizing this component.
      technique_id: T1203
      data_needed:
        - Process creation logs (e.g., Sysmon Event ID 1, Linux auditd)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability exists in the scanPoly() function of the picttoppm converter.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Netpbm to 10.86.51 or later
      owner: IT Operations
      addresses: CVE-2026-120431
      evidence: Vendor patch availability
    - priority: immediate
      action: Upgrade Netpbm to 10.86.51, 11.02.30, 11.15.08 or later
      owner: IT Operations
      addresses: CVE-2026-120432
      evidence: Netpbm before 10.86.51, 11.02.30, and 11.15.08 contains an integer overflow vulnerability
    - priority: immediate
      action: Upgrade Netpbm to version 10.86.51, 11.02.30, or 11.15.08 or later to patch CVE-2026-120433
      owner: IT Operations
      addresses: CVE-2026-120433
      evidence: Netpbm before 10.86.51, 11.x before 11.02.30, and 11.03 before 11.15.08 contains a stack-based buffer overflow
    - priority: immediate
      action: Upgrade Netpbm to 10.86.51, 11.02.30, or 11.15.08.
      owner: IT Operations
      addresses: CVE-2026-120434
      evidence: NVD vulnerability details regarding patched versions
updates:
  - at: "2026-11-02T15:48:44Z"
    level: L2
    summary: added coverage for Netpbm (< 10.86.51, < 11.02.30, < 11.15.08)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120432
  - at: "2026-11-02T15:48:49Z"
    level: L2
    summary: added coverage for Netpbm (< 10.86.51, 11.02.30, 11.15.08)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120433
  - at: "2026-11-02T15:48:54Z"
    level: L2
    summary: added coverage for Netpbm (< 10.86.51, 11.x < 11.02.30, 11.03 < 11.15.08)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120434
---

Netpbm versions before 10.86.51, 11.x before 11.02.29, and 11.03 before 11.15.07 are affected by a heap-based buffer overflow vulnerability in the `sgitopnm` utility. The flaw exists within the `readChannels()` function and is triggered when processing RLE-compressed SGI images containing an oversized offset table. Successful exploitation can result in application crashes or arbitrary code execution.

## Impact
Successful exploitation may lead to a crash of the `sgitopnm` utility (Denial of Service) or arbitrary code execution in the context of the user executing the tool.

## Recommendation
- Inventory all systems utilizing Netpbm or libraries relying on `sgitopnm`.
- Update Netpbm to version 10.86.51, 11.02.29, 11.15.07, or later to address the vulnerability.
- Implement file integrity monitoring for high-risk input processing pipelines that utilize legacy image processing libraries.
