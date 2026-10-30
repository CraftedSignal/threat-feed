---
brief_id: brief-2026-10-30-scribus-heap-oob
event_id: brief-2026-10-30-scribus-heap-oob
revision: 1
activity_at: "2026-10-30T17:36:29Z"
title: 'Scribus: Heap out-of-bounds write in PSD loader (CVE-2026-104061)'
slug: 2026-10-scribus-heap-oob
description: Scribus versions prior to 1.6.7 contain a heap out-of-bounds write vulnerability in the PSD loader that allows attackers to trigger memory corruption via a malicious file.
date: "2026-10-30T17:36:29Z"
lastmod: "2026-10-30T17:36:37Z"
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
cpes:
  - cpe:2.3:a:scribus:scribus:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - desktop-application
vendors:
  - Scribus
products:
  - Scribus (< 1.6.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can convince users to place or import a crafted PSD file to corrupt heap memory, causing crashes and potentially code execution as the user.
    confidence_band: high
cves:
  - id: CVE-2026-104061
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-104062
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104061
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104062
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Scribus to 1.6.7 or later on all user workstations
      owner: IT Operations
      due: 72h
      evidence: Scribus before 1.6.7 contains a heap out-of-bounds write vulnerability
    - action: Patch all Scribus instances to version 1.6.7 or later.
      owner: IT Operations
      due: 72h
      evidence: Scribus before 1.6.7 contains a heap buffer overflow vulnerability.
  hunt_leads:
    - lead: Identify endpoints with Scribus versions < 1.6.7 installed
      technique_id: T1203
      data_needed:
        - Installed software inventory (e.g., EDR/Asset management tools)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Scribus before 1.6.7 contains a heap out-of-bounds write vulnerability
    - lead: Identify endpoints where Scribus is installed and scan for recently opened or imported files with the .pict extension.
      technique_id: T1203
      data_needed:
        - File audit logs (e.g., Windows USN Journal or Linux fsnotify/auditd)
        - Application MRU (Most Recently Used) files
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can craft a PICT file whose bytesPerLine exceeds the QImage scanline size, so placing or importing it crashes Scribus.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Scribus to 1.6.7
      owner: IT Operations
      addresses: CVE-2026-104061
      evidence: Scribus before 1.6.7 contains a heap out-of-bounds write vulnerability
    - priority: immediate
      action: Upgrade Scribus to 1.6.7.
      owner: IT Operations
      addresses: CVE-2026-104062
      evidence: Scribus before 1.6.7 contains a heap buffer overflow vulnerability.
updates:
  - at: "2026-10-30T17:36:37Z"
    level: L2
    summary: added coverage for Scribus (< 1.6.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104062
---

Scribus versions before 1.6.7 are susceptible to a heap out-of-bounds write vulnerability within the 'scimgdataloader_psd' component. The vulnerability arises from the application using unchecked values sourced from PSD files as lookup array indexes. An attacker can exploit this by convincing a victim to import or open a crafted PSD file, leading to application crashes or the potential for arbitrary code execution within the context of the user running the application.

## Impact
Successful exploitation allows an attacker to corrupt heap memory, which can lead to service disruption via crashes or arbitrary code execution with the privileges of the user running the Scribus application.

## Recommendation
- Update all Scribus installations to version 1.6.7 or later immediately to remediate the vulnerability in the PSD file parser.
- Implement file integrity monitoring or application allowlisting if applicable to restrict the origin of PSD files imported into the organization's desktop environment.
