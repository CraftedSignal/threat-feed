---
title: Suspicious Script Interpreter Execution from Environment Variable Folders
slug: 2024-01-suspicious-script-execution
description: Malware may execute scripts from suspicious directories accessible via environment variables using script interpreters like cscript, wscript, mshta, and powershell to evade detection.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
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

Attackers may attempt to execute malicious scripts from suspicious directories or folders accessible by environment variables. This technique leverages script interpreters such as `cscript.exe`, `wscript.exe`, `mshta.exe`, and `powershell.exe` to run scripts from locations like the Temp directory, the Public user folder, or other user profile directories. The use of these locations can help attackers evade detection, as security tools may not thoroughly inspect files executed from these typically benign locations. This activity has been associated with threat actors such as Shuckworm, known to target Ukraine military.

## Attack Chain

1.  The attacker gains initial access, potentially through phishing or exploiting a software vulnerability.
2.  A malicious script is dropped into a suspicious folder such as `C:\Users\Public\`, `%TEMP%`, or `C:\Users\<username>\AppData\Local\Temp`.
3.  The attacker uses `cscript.exe`, `wscript.exe`, or `mshta.exe` to execute the dropped script. The command line may contain flags to bypass execution policies (e.g., `-ExecutionPolicy bypass`) or hide the window (e.g., `-w hidden`).
4.  Alternatively, PowerShell may be invoked with the `-ep bypass` or `-ExecutionPolicy Bypass` flags, along with a command to execute the script located in the temporary folder.
5.  The script executes, performing malicious actions such as downloading additional payloads, establishing persistence, or exfiltrating data.
6.  The script may leverage built-in Windows utilities for further malicious activities.
7.  The attacker achieves their objective, such as data theft or system compromise.

## Impact

Successful exploitation can lead to a range of damaging outcomes, including system compromise, data theft, and further propagation of malware within the network. Organizations may experience data breaches, financial losses, and reputational damage. The compromise of systems can also disrupt business operations and require extensive recovery efforts.

## Recommendation

*   Deploy the Sigma rule `Script Interpreter Execution From Suspicious Folder` to your SIEM to detect suspicious script executions.
*   Monitor process creation events with a focus on script interpreters (`cscript.exe`, `wscript.exe`, `mshta.exe`, `powershell.exe`) executing from suspicious directories, using the `logsource` and `detection` sections of the Sigma rule as a guide.
*   Tune the filters in the Sigma rule based on your environment to reduce false positives, as described in the `falsepositives` section.
*   Review and block any observed malicious command lines containing flags like `-ep bypass`, `-ExecutionPolicy bypass`, or `-w hidden`, as detailed in the `selection_proc_flags` section of the Sigma rule.
