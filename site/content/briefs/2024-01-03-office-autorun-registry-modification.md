---
title: Office Application Autorun Registry Key Modification
slug: 2024-01-03-office-autorun-registry-modification
description: Adversaries modify Office application autostart extensibility point (ASEP) registry keys to achieve persistence and execute malicious code when Office applications are launched.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - attack.privilege-escalation
  - attack.persistence
  - attack.t1547.001
vendors:
  - Microsoft
products:
  - Microsoft Office
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
  - https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
  - https://gist.github.com/GlebSukhodolskiy/0fc5fa5f482903064b448890db1eaf9d
rules:
  - title: Detect Office Application Addin Registry Modification
    description: Detects modification of Office application add-in registry keys to establish persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Office ClickToRun Registry Modification
    description: Detects modification of Office application add-in registry keys by ClickToRun executables to prevent false positives.
    platform: sigma
    severity: informational
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers may target Microsoft Office applications' autostart extensibility points (ASEPs) in the Windows Registry to establish persistence. By modifying specific registry keys, malicious actors can ensure that their code is executed each time an Office application, such as Word, Excel, or Outlook, is launched. This technique is often employed to maintain a foothold on a compromised system. While legitimate add-ins also leverage these registry keys, unauthorized modifications can lead to the…
