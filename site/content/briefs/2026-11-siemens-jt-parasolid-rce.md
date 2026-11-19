---
brief_id: brief-2026-11-19-siemens-jt-parasolid-rce
event_id: brief-2026-11-19-siemens-jt-parasolid-rce
revision: 1
activity_at: "2026-11-19T01:27:16Z"
title: Siemens JT Open Toolkit, JT Utilities, and Parasolid Memory Corruption Vulnerabilities
slug: 2026-11-siemens-jt-parasolid-rce
description: Siemens JT Open Toolkit, JT Utilities, and Parasolid are affected by memory corruption vulnerabilities triggered by parsing specially crafted JT files, potentially leading to arbitrary code execution or application crashes.
date: "2026-11-19T01:27:16Z"
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
cpes:
  - cpe:2.3:a:siemens:jt_open:*:*:*:*:*:*:*:*
  - cpe:2.3:a:siemens:jt_utilities:*:*:*:*:*:*:*:*
  - cpe:2.3:a:siemens:parasolid:*:*:*:*:*:*:*:*
vendors:
  - Siemens
products:
  - JT Open Toolkit
  - JT Utilities
  - Parasolid
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    subtechnique_id: T1204.002
    subtechnique_name: Malicious File
    evidence: If a user is tricked to open a malicious JT file with any of the affected products, this could cause the application to crash or potentially lead to arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2023-30795
    cvss: 7.8
    epss: 0.00218
    kev_status: "false"
  - id: CVE-2023-30796
    kev_status: "false"
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-23-222-03
  - https://cveawg.mitre.org/api/cve/CVE-2023-30795
  - https://cveawg.mitre.org/api/cve/CVE-2023-30796
action_plan:
  hunt_leads:
    - lead: Identify execution of Siemens JT Open, JT Utilities, or Parasolid processes that are associated with the opening of files from untrusted locations (e.g., downloads folder, temporary directories, or external storage) to detect potential exploitation of memory corruption vulnerabilities.
      technique_id: T1204
      data_needed:
        - Process Command Line
        - File Path
        - Parent Process Name
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: If a user is tricked to open a malicious JT file with any of the affected products, this could cause the application to crash or potentially lead to arbitrary code execution.
---

## Overview
Vulnerabilities have been identified in Siemens JT Open Toolkit, JT Utilities, and Parasolid products (CVE-2023-30795 and CVE-2023-30796) caused by an out-of-bounds read past the end of an allocated structure while parsing specially crafted JT files. Successful exploitation may allow an attacker to execute code in the context of the current process.

## Attack Chain
An attacker provides a specially crafted JT file to a user. If the user is tricked into opening the malicious file with an affected product, the application may crash or execute arbitrary code.

## Impact
Successful exploitation can lead to arbitrary code execution in the context of the current process.

## Recommendation
- Update JT Open Toolkit to V11.4 or later.
- Update JT Utilities to V13.4 or later.
- Update Parasolid V34.0 to V34.0.253 or later.
- Update Parasolid V34.1 to V34.1.243 or later.
- Update Parasolid V35.0 to V35.0.177 or later.
- Update Parasolid V35.1 to V35.1.073 or later.
- Do not open untrusted files using these applications.
- Follow industrial security guidelines, including minimizing network exposure and isolating control system networks.
