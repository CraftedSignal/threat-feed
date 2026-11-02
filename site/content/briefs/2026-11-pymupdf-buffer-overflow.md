---
brief_id: brief-2026-11-02-pymupdf-buffer-overflow
event_id: brief-2026-11-02-pymupdf-buffer-overflow
revision: 1
activity_at: "2026-11-02T23:48:11Z"
title: 'PyMuPDF: Stack-based buffer overflow in JM_set_annot_callout_line (CVE-2026-120752)'
slug: 2026-11-pymupdf-buffer-overflow
description: PyMuPDF versions prior to 2.0 contain a stack-based buffer overflow in the JM_set_annot_callout_line function, allowing remote code execution via specifically crafted callout arguments in Page.add_freetext_annot.
date: "2026-11-02T23:48:11Z"
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
  validation_status: Source documentation verified; no observable IOCs or log patterns provided.
cpes:
  - cpe:2.3:a:pymupdf:pymupdf:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - code-execution
  - buffer-overflow
vendors:
  - PyMuPDF
products:
  - PyMuPDF (< 2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers who control the callout argument passed to Page.add_freetext_annot() can supply four or more points to overwrite the stack frame, crashing the process or executing code.
    confidence_band: high
cves:
  - id: CVE-2026-120752
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120752
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade PyMuPDF dependencies to version 2.0 or newer.
      owner: IT Operations
      due: 72h
      evidence: PyMuPDF 1.25.3 before 2.0 contains a stack-based buffer overflow
  hunt_leads:
    - lead: Identify applications using PyMuPDF to process untrusted PDF inputs
      technique_id: T1203
      data_needed:
        - Application dependency manifests
        - SBOM reports
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Attackers who control the callout argument passed to Page.add_freetext_annot() can supply four or more points to overwrite the stack frame
  mitigation_plan:
    - priority: immediate
      action: Upgrade PyMuPDF to 2.0 or later
      owner: IT Operations
      addresses: CVE-2026-120752
      evidence: PyMuPDF 1.25.3 before 2.0 contains a stack-based buffer overflow
---

PyMuPDF versions before 2.0 contain a stack-based buffer overflow vulnerability in the function JM_set_annot_callout_line. The function fails to validate the number of callout points supplied by the caller, copying them into a fixed three-element stack array. An attacker controlling the callout argument passed to the Page.add_freetext_annot method can provide four or more points to overwrite the stack frame. Successful exploitation may result in a crash of the host process or arbitrary code execution.

## Impact

Successful exploitation allows for memory corruption within the application process, leading to denial of service via process crash or potential arbitrary code execution under the context of the user or service running the PyMuPDF library.

## Recommendation

Upgrade all instances of PyMuPDF to version 2.0 or later immediately to incorporate the bounds checking fix for the JM_set_annot_callout_line function. Perform an inventory of internal applications and third-party software that utilize the PyMuPDF library to identify instances requiring updates.
