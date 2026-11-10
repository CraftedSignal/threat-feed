---
brief_id: brief-2026-11-10-ghostscript-dsafer-bypass
event_id: brief-2026-11-10-ghostscript-dsafer-bypass
revision: 1
activity_at: "2026-11-10T02:04:48Z"
title: 'Ghostscript: -dSAFER bypass in .putgstringcopy procedure (CVE-2026-125396)'
slug: 2026-11-ghostscript-dsafer-bypass
description: Ghostscript versions prior to 10.08.0 contain a -dSAFER bypass vulnerability in the .putgstringcopy procedure, allowing attackers to leverage a use-after-free condition to achieve arbitrary code execution via crafted PostScript or PDF files.
date: "2026-11-10T02:04:48Z"
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
vendors:
  - Artifex Software
products:
  - Ghostscript (< 10.08.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply crafted PostScript or PDF documents that trigger a type error, recover .forceput via a custom error handler, and cause a use-after-free across save/restore to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-125396
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125396
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
---

Ghostscript before version 10.08.0 is vulnerable to a -dSAFER bypass in the .putgstringcopy procedure located in gs_fonts.ps. The vulnerability arises because the procedure calls the privileged .forceput operator without validating operand types. An attacker can supply a specially crafted PostScript or PDF document that triggers a deliberate type error. By recovering the .forceput operator through a custom error handler, an attacker can manipulate memory to trigger a use-after-free condition during save and restore operations, leading to arbitrary code execution within the context of the Ghostscript interpreter.

## Impact
Successful exploitation allows for arbitrary code execution in the context of the user or service running the Ghostscript interpreter. This is critical for applications that process untrusted user-supplied PostScript or PDF files (e.g., print servers, document converters, or automated imaging pipelines).

## Recommendation
- Update all installations of Ghostscript to version 10.08.0 or later immediately.
- Audit applications that integrate Ghostscript to identify and isolate processing of untrusted document inputs.
- Implement sandboxing for the Ghostscript process to limit the impact of potential code execution if immediate patching is not possible.
