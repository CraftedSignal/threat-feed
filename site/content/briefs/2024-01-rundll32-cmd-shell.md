---
title: Command Shell Activity Started via RunDLL32
slug: 2024-01-rundll32-cmd-shell
description: Adversaries abuse RunDLL32, a legitimate Windows utility, to execute command shells (cmd.exe or PowerShell) for malicious purposes, bypassing security controls.
date: "2024-01-03T18:21:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - rundll32
  - command-shell
  - proxy-execution
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/011/
rules:
  - title: Detect Command Shell Activity Started via RunDLL32
    description: Identifies command shell activity (cmd.exe or powershell.exe) started via RunDLL32, excluding known legitimate uses.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.003
      - T1218.011
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious RunDLL32 Command Line Parameters
    description: Detects rundll32.exe being used with unusual or suspicious parameters.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1218.011
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers commonly abuse RunDLL32 to execute malicious code by proxying command shell execution. This technique allows attackers to bypass application control and execute arbitrary commands. This activity typically involves rundll32.exe spawning cmd.exe or powershell.exe. Defenders need to monitor for this activity, especially when unexpected DLLs or functions are being executed, as this can indicate malicious intent. This activity has been observed across multiple environments where adversaries attempt to gain a foothold or execute commands discreetly.

## Attack Chain

1.  The attacker gains initial access to the system through an existing vulnerability or compromised credentials.
2.  The attacker uses RunDLL32 to execute a malicious DLL. `rundll32.exe <path_to_dll>,<export_name>`
3.  The malicious DLL contains code to execute a command shell.
4.  RunDLL32 spawns a command shell (cmd.exe or powershell.exe).
5.  The command shell executes commands specified by the attacker.
6.  The attacker performs reconnaissance activities, such as gathering system information or network configurations using `ipconfig` or `whoami` commands executed within the spawned shell.
7.  The attacker attempts lateral movement by using the command shell to access other systems on the network.
8.  The attacker achieves their final objective, such as data exfiltration or establishing persistence.

## Impact

Successful exploitation allows attackers to execute arbitrary commands, potentially leading to credential compromise, data theft, or system compromise. The impact is typically limited to the privileges of the user account under which the command shell is running, but can lead to domain compromise if a privileged account is targeted.

## Recommendation

*   Monitor process creation events for cmd.exe or powershell.exe with rundll32.exe as the parent process, excluding known legitimate uses (rule: "Detect Command Shell Activity Started via RunDLL32").
*   Inspect the command-line arguments of rundll32.exe processes to identify any suspicious or unusual DLLs or functions being executed.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Enable Sysmon process-creation logging to activate the rules above.
