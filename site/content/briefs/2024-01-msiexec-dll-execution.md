---
title: Msiexec Arbitrary DLL Execution
slug: 2024-01-msiexec-dll-execution
description: Adversaries may abuse the msiexec.exe utility to proxy the execution of malicious DLL payloads, bypassing application control and other defenses.
date: "2024-01-02T12:00:00Z"
severities:
  - medium
tags:
  - defense-evasion
  - proxy-execution
  - msiexec
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
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
  - https://twitter.com/_st0pp3r_/status/1583914515996897281
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_msiexec_execute_dll.yml
rules:
  - title: Suspicious Msiexec Execute Arbitrary DLL
    description: Detects suspicious execution of msiexec.exe to execute arbitrary DLLs.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
  - title: Msiexec Network Connection
    description: Detects msiexec.exe initiating network connections, which is unusual
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Msiexec.exe is the command-line utility for the Windows Installer, commonly used to execute installation packages (.msi). Attackers are known to abuse msiexec.exe to proxy the execution of arbitrary DLLs, a technique that helps bypass application control and evade detection. This approach leverages the trusted nature of msiexec.exe to execute malicious code, making it harder for security tools to identify and block the activity. The abuse of msiexec.exe has been observed in various attack…
