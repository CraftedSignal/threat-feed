---
title: Suspicious Script Interpreter Execution from Environment Variable Folders
slug: 2024-01-suspicious-script-execution
description: Malware may execute scripts from suspicious directories accessible via environment variables using script interpreters like cscript, wscript, mshta, and powershell to evade detection.
date: "2024-01-03T14:30:00Z"
severities:
  - high
tags:
  - execution
  - script-execution
  - malware
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_script_exec_from_env_folder.yml
  - https://www.virustotal.com/gui/file/91ba814a86ddedc7a9d546e26f912c541205b47a853d227756ab1334ade92c3f
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/shuckworm-russia-ukraine-military
  - https://learn.microsoft.com/en-us/windows/win32/shell/csidl
rules:
  - title: Suspicious Script Execution from Temp Folders
    description: Detects script interpreters executing from temp folders.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
  - title: Script Interpreter with Bypass Flags
    description: Detects suspicious script execution using bypass flags.
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

Attackers may attempt to execute malicious scripts from suspicious directories or folders accessible by environment variables. This technique leverages script interpreters such as `cscript.exe`, `wscript.exe`, `mshta.exe`, and `powershell.exe` to run scripts from locations like the Temp directory, the Public user folder, or other user profile directories. The use of these locations can help attackers evade detection, as security tools may not thoroughly inspect files executed from these…
