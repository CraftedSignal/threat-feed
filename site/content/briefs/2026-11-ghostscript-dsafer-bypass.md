---
brief_id: brief-2026-11-10-ghostscript-dsafer-bypass
event_id: brief-2026-11-10-ghostscript-dsafer-bypass
revision: 3
activity_at: "2026-11-23T18:52:43Z"
revision_history:
  - revision: 2
    at: "2026-11-10T16:31:37Z"
    checksum: sha256:6e8c00d9a45e4124f538356a2f34716f23f9c1ce330f9ce82196297773df73a1
    summary: new product
    changed_fields:
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4424
  - revision: 3
    at: "2026-11-23T18:52:43Z"
    checksum: sha256:cbc88a8be79e7265e2809eef1362be9c8afa198d8095111d7dd4622273ef2cdc
    summary: poc_available
    changed_fields:
      - claim_state
      - cve_verification
      - cves
      - has_poc
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.sophos.com/en-us/blog/proof-of-concept-available-for-ghostscript-upload2shell
title: 'Ghostscript: -dSAFER bypass in .putgstringcopy procedure (CVE-2026-125396)'
slug: 2026-11-ghostscript-dsafer-bypass
description: Ghostscript versions prior to 10.08.0 contain a -dSAFER bypass vulnerability in the .putgstringcopy procedure, allowing attackers to leverage a use-after-free condition to achieve arbitrary code execution via crafted PostScript or PDF files.
date: "2026-11-10T02:04:48Z"
lastmod: "2026-11-23T18:52:20Z"
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
  validation_status: Patch released in version 10.08.0
cpes:
  - cpe:2.3:a:artifex:ghostscript:*:*:*:*:*:*:*:*
has_poc: true
vendors:
  - Artifex Software
products:
  - Ghostscript
product_versions:
  - product: Ghostscript
    range: < 10.08.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply crafted PostScript or PDF documents that trigger a type error, recover .forceput via a custom error handler, and cause a use-after-free across save/restore to execute arbitrary code.
    confidence_band: high
cve_verification:
  CVE-2026-125396:
    status: verified
    source: nvd
    checked_at: 2026-11-23T18:52:20.854905694Z
cves:
  - id: CVE-2026-125396
    cvss: 7.8
    epss: 0.00347
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125396
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4424
  - https://sploitus.com/exploit?id=1E4F8989-96F8-5CCC-908E-35A5149361F1&utm_source=rss&utm_medium=rss
  - https://www.sophos.com/en-us/blog/proof-of-concept-available-for-ghostscript-upload2shell
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Ghostscript to 10.08.0 or later
      owner: IT Operations
      due: 48h
      evidence: Ghostscript before 10.08.0 contains a -dSAFER bypass
  hunt_leads:
    - lead: Identify applications utilizing Ghostscript to process external PDF or PostScript files for anomalous process behavior
      technique_id: T1203
      data_needed:
        - Process lineage (Parent/Child relationship)
        - Execution of shell commands or network connections spawned by ghostscript/gs processes
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can... cause a use-after-free... to execute arbitrary code.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Ghostscript to 10.08.0
      owner: IT Operations
      addresses: CVE-2026-125396
      evidence: Ghostscript before 10.08.0 contains a -dSAFER bypass vulnerability
updates:
  - at: "2026-11-10T16:30:26Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4424
  - at: "2026-11-23T18:52:20Z"
    level: L2
    summary: poc_available
    sources:
      - sophos-xops
    source_urls:
      - https://www.sophos.com/en-us/blog/proof-of-concept-available-for-ghostscript-upload2shell
---

## Overview
Ghostscript before version 10.08.0 is vulnerable to a -dSAFER bypass in the .putgstringcopy procedure located in gs_fonts.ps. The vulnerability arises because the procedure calls the privileged .forceput operator without validating operand types. An attacker can supply a specially crafted PostScript or PDF document that triggers a deliberate type error. By recovering the .forceput operator through a custom error handler, an attacker can manipulate memory to trigger a use-after-free condition during save and restore operations, leading to arbitrary code execution within the context of the Ghostscript interpreter.

## Impact
Successful exploitation allows for arbitrary code execution in the context of the user or service running the Ghostscript interpreter. This is critical for applications that process untrusted user-supplied PostScript or PDF files (e.g., print servers, document converters, or automated imaging pipelines).

## Recommendation
- Update all installations of Ghostscript to version 10.08.0 or later immediately.
- Audit applications that integrate Ghostscript to identify and isolate processing of untrusted document inputs.
- Implement sandboxing for the Ghostscript process to limit the impact of potential code execution if immediate patching is not possible.
