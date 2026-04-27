---
title: Windows EventLog Autologger Session Disabled via Registry Modification
slug: 2024-01-autologger-disable
description: Adversaries may attempt to disable Windows EventLog autologger sessions via registry modification to evade detection and prevent security monitoring of early boot activities and system events.
date: "2024-01-09T14:22:00Z"
severities:
  - high
tags:
  - attack.defense-evasion
  - attack.t1562.002
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session
  - https://ptylu.github.io/content/report/report.html?report=25
  - https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_autologger_session_registry_modification.yml
rules:
  - title: Windows EventLog Autologger Session Registry Modification via Reg.exe
    description: Detects attempts to disable Windows EventLog autologger sessions via registry modification using reg.exe
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Windows EventLog Autologger Session Registry Modification via PowerShell
    description: Detects attempts to disable Windows EventLog autologger sessions via registry modification using PowerShell
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may disable Windows EventLog autologger sessions by modifying specific registry keys, thus evading detection and preventing security monitoring of early boot activities and system events. The AutoLogger event tracing session records events early in the operating system boot process, allowing applications and device drivers to capture traces before user login. Disabling these sessions can blind security monitoring tools, especially those focused on early boot activity, making it harder…
