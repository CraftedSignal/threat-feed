---
title: Suspicious Script Interpreter Execution from Environment Variable Folders
slug: 2024-01-susp-script-exec
description: Adversaries may execute script interpreters such as cscript, wscript, mshta, or powershell from suspicious directories accessible via environment variables to evade detection and execute malicious scripts.
date: "2024-01-03T12:00:00Z"
severities:
  - high
tags:
  - attack.execution
  - attack.t1059
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
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.virustotal.com/gui/file/91ba814a86ddedc7a9d546e26f912c541205b47a853d227756ab1334ade92c3f
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/shuckworm-russia-ukraine-military
  - https://learn.microsoft.com/en-us/windows/win32/shell/csidl
rules:
  - title: Suspicious PowerShell Execution from Temp Folders
    description: Detects PowerShell execution from common temp folders with bypass flags.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Script Interpreter from User Profile Folders
    description: Detects cscript, wscript, or mshta executing from user profile directories like Favorites or Contacts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers often leverage script interpreters like cscript.exe, wscript.exe, mshta.exe, and powershell.exe to execute malicious code. This activity becomes more suspicious when these interpreters are launched from directories referenced by environment variables commonly associated with temporary storage, such as %TEMP%, %PUBLIC%, or within user profile directories like Favorites or Contacts. This behavior is often indicative of malware attempting to evade detection by residing in locations less…
