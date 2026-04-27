---
title: Qualcomm Memory Corruption Vulnerability CVE-2026-21382
slug: 2026-04-qualcomm-buffer-overflow
description: CVE-2026-21382 is a memory corruption vulnerability related to handling power management requests with improperly sized input/output buffers, potentially leading to code execution.
date: "2026-04-06T16:16:31Z"
severities:
  - high
tags:
  - cve-2026-21382
  - buffer-overflow
  - memory-corruption
  - qualcomm
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2026-21382
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21382
  - https://docs.qualcomm.com/product/publicresources/securitybulletin/april-2026-bulletin.html
ioc_counts:
  url: 1
rules:
  - title: Suspicious Child Process of Power Management Service
    description: Detects a power management service spawning an unusual child process, which may indicate exploitation or compromise.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Power Management Process Accessing Sensitive Memory Regions
    description: Detects power management processes attempting to write to protected or system memory regions.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-21382 describes a memory corruption vulnerability in Qualcomm products. The vulnerability stems from improper handling of power management requests with inadequately sized input/output buffers, which could lead to a buffer overflow (CWE-120). This vulnerability was reported by Qualcomm, Inc., and assigned a CVSS v3.1 score of 7.8. While the specific affected products are not detailed in the provided source, the advisory indicates it is part of the April 2026 Qualcomm security bulletin…
