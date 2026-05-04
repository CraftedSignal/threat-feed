---
title: Command Shell Activity Started via RunDLL32
slug: 2026-05-rundll32-cmd-shell
description: This rule detects command shell activity, such as cmd.exe or powershell.exe, initiated by RunDLL32, a technique commonly abused by attackers to execute malicious code and bypass security controls.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - execution
  - command-shell
  - rundll32
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
products:
  - M365 Defender
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - windows
mitre_ttps:
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
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_command_shell_via_rundll32.toml
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/011/
rules:
  - title: Command Shell Activity Started via RunDLL32
    description: Detects command shell activity (cmd.exe or powershell.exe) started via RunDLL32, which is commonly abused by attackers.
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
  - title: Suspicious RunDLL32 Parent Process CommandLine
    description: Detects suspicious command lines used by RunDLL32.exe, indicating potential exploitation.
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

Attackers commonly abuse RunDLL32, a legitimate Windows utility, to execute malicious code by hosting it within DLLs. This technique allows adversaries to launch command shells like cmd.exe or PowerShell, effectively bypassing traditional security controls. Defenders should be aware of this technique because it provides a stealthy way for attackers to execute arbitrary commands, potentially leading to further compromise of the system. This activity is detected by monitoring for command shells initiated by RunDLL32, while excluding known benign patterns to reduce false positives. The detection rule was last updated on 2026/05/04 and supports multiple data sources, including Elastic Defend, Microsoft Defender XDR, and Sysmon.

## Attack Chain

1.  The attacker gains initial access to the system through an exploit or social engineering.
2.  The attacker uses RunDLL32.exe to execute a malicious DLL.
3.  RunDLL32.exe loads the specified DLL into memory.
4.  The malicious DLL contains code to execute a command shell (cmd.exe or powershell.exe).
5.  RunDLL32.exe spawns a command shell process.
6.  The attacker uses the command shell to execute commands for reconnaissance.
7.  The attacker may use the command shell to download additional payloads.
8.  The attacker leverages the command shell to perform lateral movement.

## Impact

Successful exploitation allows attackers to execute arbitrary commands on the compromised system. While the rule is rated "low" severity, this initial access can lead to credential access (T1552) and further lateral movement within the network. Attackers can potentially gain full control of the system, leading to data theft, system disruption, or other malicious activities.

## Recommendation

*   Deploy the Sigma rule "Command Shell Activity Started via RunDLL32" to your SIEM and tune for your environment.
*   Enable Sysmon process creation logging (Event ID 1) to provide the necessary data for this detection.
*   Review the process details of RunDLL32.exe to confirm the parent-child relationship with the command shell, helping to reduce false positives.
*   Implement enhanced monitoring for rundll32.exe and related processes to detect similar activities in the future and improve response times.
