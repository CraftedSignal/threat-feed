---
brief_id: brief-2026-10-22-cfitsio-oob-write
event_id: brief-2026-10-22-cfitsio-oob-write
revision: 1
activity_at: "2026-10-22T22:31:05Z"
title: 'NASA CFITSIO: Out-of-bounds write in getcols.c (CVE-2026-115504)'
slug: 2026-10-cfitsio-oob-write
description: A vulnerability in CFITSIO up to version 4.7.0 allows for arbitrary code execution through an out-of-bounds write in the ffgcls2 function when processing maliciously crafted FITS files.
date: "2026-10-22T22:31:05Z"
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
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:nasa:cfitsio:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - file-processing
vendors:
  - NASA
products:
  - CFITSIO (<= 4.7.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can supply a crafted FITS file that overflows a fixed 28,800-byte stack buffer and the caller's string array, enabling arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-115504
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115504
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory software dependencies for libraries using CFITSIO <= 4.7.0
      owner: Security Engineering
      due: 72h
      evidence: Vulnerability affects CFITSIO versions through 4.7.0
  mitigation_plan:
    - priority: immediate
      action: Upgrade CFITSIO to a version later than 4.7.0 once patches are available
      owner: IT Operations
      addresses: CVE-2026-115504
      evidence: CFITSIO through 4.7.0 contains an out-of-bounds write vulnerability
---

CFITSIO version 4.7.0 and earlier contains an out-of-bounds write vulnerability in the ffgcls2() function located in getcols.c. The vulnerability arises because the library trusts attacker-controlled heap descriptor lengths for variable-length string columns. A crafted FITS file can trigger an overflow of a fixed 28,800-byte stack buffer, potentially leading to arbitrary code execution in the context of the application parsing the file.

## Impact
Successful exploitation allows an attacker to achieve arbitrary code execution on systems that process malicious FITS files using the affected CFITSIO library.

## Recommendation
- Inventory systems and software applications within the environment that utilize the CFITSIO library for FITS file processing.
- Prioritize updates to the latest version of CFITSIO once the vendor releases a patch addressing CVE-2026-115504.
- Implement file format validation or utilize sandboxing when processing untrusted FITS files until the library can be updated.
