---
title: Suspicious Registry Modifications by Scripting Engines
slug: 2024-01-29-susp-reg-mod
description: The use of scripting engines like WScript and CScript to modify the Windows registry can indicate an attempt to bypass standard tools and evade defenses, potentially for persistence or other malicious activities.
date: "2024-01-29T12:00:00Z"
severities:
  - medium
tags:
  - defense-evasion
  - persistence
  - execution
  - registry-modification
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.nextron-systems.com/2025/07/29/detecting-the-most-popular-mitre-persistence-method-registry-run-keys-startup-folder/
  - https://www.linkedin.com/posts/mauricefielenbach_livingofftheland-redteam-persistence-activity-7344801774182051843-TE00/
rules:
  - title: Registry Tampering by WScript/CScript
    description: Detects registry modifications made by WScript or CScript processes, excluding known legitimate paths.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1059.005
      - T1112
      - T1547.001
    data_sources:
      - registry_event
      - windows
  - title: Registry Tampering by MSHTA
    description: Detects registry modifications made by mshta.exe, which can indicate attempts to bypass standard tools.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1112
      - T1547.001
    data_sources:
      - registry_event
      - windows
rules_count: 2
---

Attackers may leverage scripting engines, such as `wscript.exe` and `cscript.exe`, to directly modify the Windows Registry. These scripting engines are often abused for malicious purposes, including establishing persistence, escalating privileges, or disabling security controls. These scripting engines can modify the registry without using standard tools like `regedit.exe` or `reg.exe`, making it harder to detect malicious registry changes. Defenders should be aware of processes using these…
