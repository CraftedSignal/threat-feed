---
title: Microsoft Brokering File System Double Free Privilege Escalation (CVE-2026-32219)
slug: 2026-04-ms-brokering-file-system-privesc
description: CVE-2026-32219 is a double free vulnerability in the Microsoft Brokering File System, allowing an authorized attacker to escalate privileges locally on a vulnerable Windows system.
date: "2026-04-14T18:17:29Z"
severities:
  - high
tags:
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32219
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32219
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32219
rules:
  - title: Detect Suspicious Process Creation with Uncommon Parent
    description: Detects suspicious process creation events where a process is spawned from an unexpected parent process, potentially indicating exploitation or malicious activity. This rule identifies when a system process (e.g., cmd.exe, powershell.exe) is launched by a user process (e.g., a downloaded executable).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Brokering File System Process Creation
    description: Detects process creations related to the Microsoft Brokering File System.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32219 is a critical vulnerability affecting the Microsoft Brokering File System. This double free vulnerability allows an attacker with local access to elevate their privileges on the system. While the specific details of exploitation are not provided in the advisory, the vulnerability exists within a core component of the Windows operating system, meaning successful exploitation could lead to complete system compromise. The vulnerability was reported to Microsoft and assigned…
