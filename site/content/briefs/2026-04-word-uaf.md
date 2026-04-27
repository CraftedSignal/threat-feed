---
title: Microsoft Office Word Use-After-Free Vulnerability (CVE-2026-33095)
slug: 2026-04-word-uaf
description: A use-after-free vulnerability in Microsoft Office Word (CVE-2026-33095) could allow a local attacker to execute arbitrary code by opening a specially crafted document.
date: "2026-04-15T12:00:00Z"
severities:
  - high
exploited: true
tags:
  - cve-2026-33095
  - use-after-free
  - microsoft-office
  - word
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-33095
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33095
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33095
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Child Process of Word
    description: Detects suspicious child processes spawned by Microsoft Word, which may indicate exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Network Connection from Word
    description: Detects network connections initiated from Microsoft Word, which may indicate exploitation attempts leading to C2 activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-33095 describes a use-after-free vulnerability within Microsoft Office Word. Exploitation of this vulnerability could permit an attacker to execute arbitrary code on a vulnerable system. The attack requires user interaction, as the victim must open a malicious Word document. The vulnerability was reported to Microsoft and assigned a CVSS v3.1 base score of 7.8, indicating a high severity. While the vulnerability is local, successful exploitation leads to high impact in terms of…
