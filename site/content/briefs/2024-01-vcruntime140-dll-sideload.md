---
title: Potential Vcruntime140 DLL Sideloading
slug: 2024-01-vcruntime140-dll-sideload
description: Detects potential DLL sideloading of vcruntime140.dll, a common C++ runtime library, often used by threat actors like APT29 (via WinELOADER) to load malicious payloads under the guise of legitimate applications, leading to defense evasion, persistence, and privilege escalation.
date: "2024-01-03T12:00:00Z"
severities:
  - high
actors:
  - APT29
tags:
  - dll-sideloading
  - vcruntime140.dll
  - apt29
  - wineloader
  - defense-evasion
  - persistence
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Visual C++ Redistributable
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://www.mandiant.com/resources/blog/apt29-wineloader-german-political-parties
  - https://www.zscaler.com/blogs/security-research/european-diplomats-targeted-spikedwine-wineloader
  - https://www.nextron-systems.com/2023/09/15/detecting-janelarat-with-yara-and-thor/
rules:
  - title: Suspicious Vcruntime140 DLL Load from Non-Standard Path
    description: Detects vcruntime140.dll loaded from a non-standard directory, which could indicate DLL sideloading.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1574.001
    data_sources:
      - image_load
      - windows
  - title: Suspicious Vcruntime140 DLL Load Without Microsoft Signature
    description: Detects vcruntime140.dll being loaded without a valid Microsoft signature, which could indicate a malicious sideloaded DLL.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1574.001
    data_sources:
      - image_load
      - windows
rules_count: 2
---

This brief addresses the threat of DLL sideloading, specifically targeting the `vcruntime140.dll` library, a common component of the Visual C++ Redistributable. Threat actors, including APT29, have been observed exploiting this technique to load malicious payloads disguised as legitimate applications. By placing a malicious `vcruntime140.dll` in the same directory as a vulnerable application (e.g., SqlWriter, SqlDumper), attackers can hijack the application's execution flow. This allows them to…
