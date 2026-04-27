---
title: Microsoft Excel Use-After-Free Vulnerability (CVE-2026-32189)
slug: 2026-04-excel-uaf
description: CVE-2026-32189 is a use-after-free vulnerability in Microsoft Excel that allows a local attacker to execute arbitrary code by exploiting memory corruption.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - use-after-free
  - code-execution
  - excel
  - cve-2026-32189
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-32189
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32189
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32189
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Child Process of Excel
    description: Detects unusual child processes spawned by Excel. This may indicate exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Excel Creating Executable Files
    description: Detects Excel creating executable files in suspicious locations, potentially indicating an exploit.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-32189 is a use-after-free vulnerability affecting Microsoft Office Excel. This flaw can be exploited by an attacker to execute arbitrary code on a vulnerable system. The vulnerability arises from improper memory management within the application when handling specific Excel files. While the exact versions affected are not detailed, the vulnerability was reported on April 14, 2026. Successful exploitation requires a user to open a specially crafted Excel file, which triggers the…
