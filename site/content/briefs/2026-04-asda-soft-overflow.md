---
title: ASDA-Soft Stack-based Buffer Overflow Vulnerability (CVE-2026-5726)
slug: 2026-04-asda-soft-overflow
description: A stack-based buffer overflow vulnerability exists in ASDA-Soft, potentially leading to arbitrary code execution, as identified by CVE-2026-5726 and reported by Deltaww with a CVSS v3.1 score of 7.8.
date: "2026-04-08T03:16:07Z"
severities:
  - high
tags:
  - buffer-overflow
  - asda-soft
  - cve-2026-5726
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
cves:
  - id: CVE-2026-5726
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5726
  - https://filecenter.deltaww.com/news/download/doc/Delta-PCSA-2026-00007_ASDA-Soft%20Stack-based%20Buffer%20Overflow%20Vulnerability%20(CVE-2026-5726).pdf
ioc_counts:
  email: 2
  url: 1
rules:
  - title: Detect Unusual ASDA-Soft Process Execution
    description: Detects unusual process execution of ASDA-Soft, which could indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect ASDA-Soft opening suspicious files
    description: Detects ASDA-Soft opening files with unusual extensions that could indicate exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-5726 describes a stack-based buffer overflow vulnerability in ASDA-Soft, a software product by Deltaww. This vulnerability, reported and assigned a CVSS v3.1 score of 7.8 by Deltaww, could allow an attacker to execute arbitrary code on a system running the affected software. Successful exploitation requires user interaction, as indicated by the CVSS vector. The specific version of ASDA-Soft affected is detailed in Deltaww's advisory Delta-PCSA-2026-00007. This vulnerability poses a…
