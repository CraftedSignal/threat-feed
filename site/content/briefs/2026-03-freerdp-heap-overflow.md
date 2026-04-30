---
title: FreeRDP Heap-Buffer-Overflow Vulnerability (CVE-2026-33982)
slug: 2026-03-freerdp-heap-overflow
description: A heap-buffer-overflow read vulnerability exists in FreeRDP versions prior to 3.24.2, specifically in the winpr_aligned_offset_recalloc() function, potentially leading to denial of service or information disclosure.
date: "2026-03-30T22:16:19Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - freerdp
  - heap-buffer-overflow
  - cve-2026-33982
  - rdp
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-33982
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33982
  - https://github.com/FreeRDP/FreeRDP/commit/a48dbde2c8a5b8b70a9d1c045d969a71afd6284c
  - https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-8jm9-2925-g4v2
ioc_counts:
  email: 1
rules:
  - title: Detect FreeRDP Heap Buffer Overflow
    description: Detects potential exploitation attempts of FreeRDP heap buffer overflow vulnerability CVE-2026-33982 by monitoring for FreeRDP process creation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detect FreeRDP process crash
    description: Detects FreeRDP process crash that may be caused by heap buffer overflow vulnerability CVE-2026-33982.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - application
      - windows
rules_count: 2
---

CVE-2026-33982 is a heap-buffer-overflow READ vulnerability affecting FreeRDP, a widely used open-source implementation of the Remote Desktop Protocol (RDP). The vulnerability exists in versions prior to 3.24.2 and is located within the `winpr_aligned_offset_recalloc()` function. Specifically, the flaw occurs due to an out-of-bounds read 24 bytes before the allocated buffer, which could be triggered during specific RDP operations involving memory reallocation. Successful exploitation can lead…
