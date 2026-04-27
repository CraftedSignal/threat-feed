---
title: 'CVE-2026-32155: Desktop Window Manager Use-After-Free Privilege Escalation'
slug: 2026-04-dwm-uaf-privesc
description: CVE-2026-32155 is a use-after-free vulnerability in the Desktop Window Manager that allows an authorized attacker to escalate privileges locally on a Windows system.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - use-after-free
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32155
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32155
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32155
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Interaction with Desktop Window Manager
    description: Detects processes attempting to interact with dwm.exe in unusual ways, which could indicate exploit activity.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect DWM.exe Spawning Suspicious Processes
    description: Detects DWM.exe spawning child processes, which is highly unusual and could indicate exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32155 is a critical use-after-free vulnerability residing within Microsoft's Desktop Window Manager (DWM). This vulnerability allows a locally authenticated attacker to achieve privilege escalation on a vulnerable Windows system. The vulnerability exists due to improper memory management within DWM, potentially leading to exploitation and elevation of privileges from a standard user to SYSTEM. While the exact exploitation steps are not detailed, the nature of use-after-free…
