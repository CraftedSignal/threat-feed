---
title: Suspicious Script Execution from Temporary Directory
slug: 2024-01-script-exec-temp
description: This brief covers a detection for suspicious script execution, such as PowerShell, WScript, or MSHTA, originating from common temporary directories, potentially indicating malware activity.
date: "2024-01-02T14:30:00Z"
severities:
  - high
exploited: true
tags:
  - execution
  - script
  - temp
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
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_script_exec_from_temp.yml
  - https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/
rules:
  - title: Suspicious PowerShell Execution from Temp Directory
    description: Detects PowerShell execution from common temporary directories.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious MSHTA Execution from Temp Directory
    description: Detects MSHTA execution from common temporary directories.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies suspicious script executions originating from temporary directories. Threat actors often leverage temporary folders to stage and execute malicious scripts, such as PowerShell, VBScript, or even HTML applications (MSHTA) to evade detection or bypass security controls. These scripts can be delivered through various means, including phishing attacks, drive-by downloads, or as part of a multi-stage malware infection. The execution of scripts from temporary directories is…
