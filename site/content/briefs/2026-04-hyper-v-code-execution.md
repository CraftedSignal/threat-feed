---
title: Windows Hyper-V Improper Input Validation Vulnerability (CVE-2026-32149)
slug: 2026-04-hyper-v-code-execution
description: CVE-2026-32149 is a vulnerability in Windows Hyper-V due to improper input validation, which allows an authorized, local attacker to execute arbitrary code.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - hyper-v
  - code-execution
  - vulnerability
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
cves:
  - id: CVE-2026-32149
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32149
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32149
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Hyper-V Process Creation
    description: Detects potentially malicious processes spawned by Hyper-V components, which could indicate exploitation of CVE-2026-32149.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Hyper-V Configuration Changes via PowerShell
    description: Detects suspicious use of PowerShell to modify Hyper-V configurations, potentially indicative of exploit preparation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32149 describes an improper input validation vulnerability within Microsoft's Windows Hyper-V virtualization platform. The vulnerability allows a locally authenticated attacker with user-level privileges to execute arbitrary code on the system. According to the NVD, this vulnerability was reported to Microsoft and assigned a CVSS v3.1 base score of 7.3, indicating a high severity. Successful exploitation requires the attacker to have valid credentials on the system, and user…
