---
brief_id: brief-2026-11-11-librecad-heap-overflow
event_id: brief-2026-11-11-librecad-heap-overflow
revision: 1
activity_at: "2026-11-11T05:59:42Z"
title: 'LibreCAD: Heap-based out-of-bounds write in libdxfrw (CVE-2026-126497)'
slug: 2026-11-librecad-heap-overflow
description: LibreCAD versions through 2.2.1.6 contain a heap-based out-of-bounds write vulnerability in the libdxfrw library that could allow for application crashes or arbitrary code execution via a crafted DWG file.
date: "2026-11-11T05:59:42Z"
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
cpes:
  - cpe:2.3:a:librecad:librecad:*:*:*:*:*:*:*:*
vendors:
  - LibreCAD
products:
  - LibreCAD (<= 2.2.1.6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can craft an AC1018 (R2004) DWG file with malicious startOffset values that cause decompress18 to write past the heap buffer when opened, causing crashes and potential code execution.
    confidence_band: high
cves:
  - id: CVE-2026-126497
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-126497
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory LibreCAD instances across the organization.
      owner: IT Operations
      due: 48h
      evidence: LibreCAD through 2.2.1.6 contains a heap-based out-of-bounds write
  hunt_leads:
    - lead: Identify crashes of LibreCAD.exe or libre-cad process linked to DWG file handling.
      technique_id: T1203
      data_needed:
        - Windows Event Logs (Application Error), Linux system logs, or EDR process monitoring.
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: causing crashes and potential code execution
  mitigation_plan:
    - priority: immediate
      action: Advise end users to refrain from opening files from unknown sources using LibreCAD until an update is provided by the vendor.
      owner: SOC
      addresses: CVE-2026-126497
      evidence: CVE-2026-126497
---

LibreCAD versions through 2.2.1.6 are susceptible to a heap-based out-of-bounds write vulnerability located in the `dwgReader18::parseDataPage()` function of the bundled `libdxfrw` library. The vulnerability is caused by a failure to perform adequate boundary checks on buffer sizes and page offsets. An attacker can exploit this by providing a specially crafted AC1018 (R2004) DWG file containing malicious `startOffset` values, which triggers an out-of-bounds write in the `decompress18` function when the file is parsed by LibreCAD.

## Impact

Successful exploitation may result in an application crash (denial of service) or potential arbitrary code execution within the context of the user running LibreCAD.

## Recommendation

- Inventory all systems where LibreCAD is installed and identify the current version.
- Advise users to avoid opening untrusted or unsolicited DWG files until a security update is released and applied.
- Implement endpoint monitoring for anomalous LibreCAD process behavior or crash activity.
