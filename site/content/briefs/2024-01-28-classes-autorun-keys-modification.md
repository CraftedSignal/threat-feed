---
title: Windows Registry Classes Autorun Keys Modification for Persistence
slug: 2024-01-28-classes-autorun-keys-modification
description: Adversaries modify Windows Registry Classes keys to establish persistence by executing malicious code when specific file types are opened or actions are performed, potentially leading to privilege escalation and persistent access.
date: "2024-01-28T12:00:00Z"
severities:
  - medium
tags:
  - attack.privilege-escalation
  - attack.persistence
  - attack.t1547.001
vendors:
  - Microsoft
products:
  - Windows
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
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_classes.yml
rules:
  - title: Suspicious Modification of .exe Association
    description: Detects suspicious modification of the .exe file association in the registry, often used for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Modification of ShellEx DragDropHandlers
    description: Detects modifications to ShellEx DragDropHandlers, which is often abused by malware for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Suspicious CLSID Instance Modification
    description: Detects modification of CLSID Instance registry keys associated with media codecs, a common persistence location
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

Attackers can manipulate Windows Registry Classes keys, an autostart extensibility point (ASEP), to achieve persistence. This involves modifying registry entries that control how the operating system handles specific file types or shell actions. By modifying these keys, adversaries can ensure their malicious code executes whenever a user interacts with a specific file type (e.g., opening an .exe) or performs a specific action within the shell. This technique, which has been observed since at…
