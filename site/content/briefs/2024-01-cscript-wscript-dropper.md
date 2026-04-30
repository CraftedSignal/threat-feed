---
title: WScript or CScript Dropper
slug: 2024-01-cscript-wscript-dropper
description: The WScript or CScript Dropper technique involves using cscript.exe or wscript.exe to write malicious script files (js, jse, vba, vbe, vbs, wsf, wsh) to suspicious locations on a Windows system for later execution.
date: "2024-01-02T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - script-dropper
  - file-creation
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_cscript_wscript_dropper.yml
rules:
  - title: Detect WScript/CScript Writing Suspicious Files
    description: Detects the writing of files ending in jse, vbe, js, vba, vbs, wsf, wsh by cscript.exe or wscript.exe into suspicious directories.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.005
      - T1059.007
    data_sources:
      - file_event
      - windows
  - title: Detect CScript/WScript launching from unusual process
    description: Detects CScript or WScript being launched by a process that isn't explorer.exe or cmd.exe
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.005
      - T1059.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The WScript or CScript Dropper technique is a method employed by attackers to introduce malicious script files into a system. It leverages the built-in Windows scripting hosts, `cscript.exe` and `wscript.exe`, to write files with extensions commonly associated with scripting languages (e.g., `.js`, `.vbs`, `.wsf`). These scripts are often written to temporary or user-accessible directories, such as `\Temp\`, `\AppData\`, or `\Startup\`, where they can be executed later, either manually or…
