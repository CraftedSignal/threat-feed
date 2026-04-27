---
title: Print.exe Used to Dump Sensitive Files for Credential Access
slug: 2024-01-print-exe-credential-dump
description: Attackers are abusing the legitimate Windows Print.exe utility to copy sensitive files like NTDS.DIT and SAM in order to extract credentials, enabling local or remote credential access.
date: "2024-01-03T12:00:00Z"
severities:
  - high
tags:
  - credential-dumping
  - credential-access
  - windows
  - print.exe
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
references:
  - https://www.microsoft.com/en-us/security/blog/2026/02/06/active-exploitation-solarwinds-web-help-desk/
  - https://www.huntress.com/blog/credential-theft-expanding-your-reach-pt-2
  - https://lolbas-project.github.io/lolbas/Binaries/Print/
rules:
  - title: Sensitive File Dump Via Print.EXE
    description: Detects the abuse of the Print.exe utility for credential harvesting by copying sensitive files.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-evasion
    techniques:
      - T1003.002
      - T1003.003
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Print.exe Executed from Suspicious Location
    description: Detects Print.exe execution from unusual directories, indicating potential misuse.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are leveraging the `Print.exe` utility, a legitimate Windows command-line tool, to dump sensitive operating system files for credential harvesting. This technique involves using `Print.exe` to copy files like `ntds.dit`, `SAM`, `SECURITY`, and `SYSTEM` from their protected Windows directories. These files contain sensitive credential data that can be extracted offline. This activity was observed in relation to the SolarWinds Web Help Desk exploitation in early 2026. Abuse of…
