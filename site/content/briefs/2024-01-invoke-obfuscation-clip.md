---
title: Invoke-Obfuscation via Clip.exe
slug: 2024-01-invoke-obfuscation-clip
description: The use of `clip.exe` in conjunction with PowerShell and command-line obfuscation is used to evade detection.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - execution
  - obfuscation
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_use_clip.yml
rules:
  - title: Detect Invoke-Obfuscation Via Use Clip
    description: Detects Obfuscated Powershell via use Clip.exe in Scripts
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Cmd.exe with Clip and PowerShell NoLogo
    description: Detects a cmd.exe process that pipes into clip.exe and executes powershell with the NoLogo flag
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly using obfuscation techniques to evade detection, specifically leveraging `clip.exe` in conjunction with PowerShell and command-line interpreters. This combination allows for the execution of malicious code while bypassing traditional signature-based detections. This activity often includes encoding and splitting commands to avoid string-based detection. Invoke-Obfuscation is a known framework used to generate these types of payloads. Defenders should focus on detecting the specific patterns of command execution and data manipulation that are characteristic of this technique. The detection of such obfuscated PowerShell commands is crucial for identifying and mitigating potential security breaches.

## Attack Chain

1.  Attacker gains initial access to the target system (e.g., via phishing or exploiting a vulnerability).
2.  A command interpreter (cmd.exe) is invoked to execute a complex, obfuscated command.
3.  The command includes `echo` to write data to standard output, piping the output to `clip.exe`.
4.  `clip.exe` places the output (part of the malicious PowerShell code) into the clipboard.
5.  Another `cmd.exe` process invokes PowerShell to execute the content retrieved from the clipboard.
6.  PowerShell uses reflection to load and execute .NET assemblies from the clipboard.
7.  The executed code performs malicious actions, such as downloading additional payloads or establishing persistence.
8.  The clipboard content is cleared to remove traces of the injected code.

## Impact

Successful execution of obfuscated PowerShell commands can lead to a range of malicious activities, including malware installation, data theft, and remote system control. The use of `clip.exe` and other obfuscation techniques significantly hinders detection efforts, potentially allowing attackers to operate undetected for extended periods. This can result in significant financial losses, data breaches, and reputational damage for affected organizations.

## Recommendation

*   Deploy the Sigma rule "Detect Invoke-Obfuscation Via Use Clip" to your SIEM to detect command lines using `clip.exe` and obfuscated PowerShell (see rule details).
*   Monitor process creation events for instances of `cmd.exe` invoking `clip.exe` with command lines containing `echo` piped to `clip.exe` (logsource: process_creation, product: windows).
*   Inspect PowerShell execution logs for commands that access the clipboard, especially when followed by assembly loading or remote code execution (logsource: process_creation, product: windows).
