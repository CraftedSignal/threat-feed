---
title: Suspicious Explorer Child Process via DCOM
slug: 2024-01-suspicious-explorer-child-process
description: Adversaries abuse the trusted status of explorer.exe to launch malicious scripts or executables, often using DCOM to start processes like PowerShell or cmd.exe, achieving initial access, defense evasion, and execution.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - initial-access
  - defense-evasion
  - execution
  - explorer.exe
  - dcom
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1559
    technique_name: Inter-Process Communication
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/initial_access_via_explorer_suspicious_child_parent_args.toml
  - https://attack.mitre.org/techniques/T1566/
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1566/002/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://attack.mitre.org/techniques/T1059/005/
  - https://attack.mitre.org/techniques/T1559/
  - https://attack.mitre.org/techniques/T1559/001/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/005/
  - https://attack.mitre.org/techniques/T1218/010/
  - https://attack.mitre.org/techniques/T1218/011/
rules:
  - title: Suspicious Explorer Child Process - PowerShell
    description: Detects PowerShell processes spawned by explorer.exe with the '-Embedding' argument, indicating potential exploitation via DCOM.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1559.001
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Explorer Child Process - Scripting Engines
    description: Detects scripting engines like cmd.exe, cscript.exe, wscript.exe, mshta.exe, regsvr32.exe, or rundll32.exe spawned by explorer.exe with the '-Embedding' argument, indicating potential exploitation via DCOM.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - initial_access
    techniques:
      - T1059.003
      - T1218.005
      - T1218.010
      - T1218.011
      - T1559.001
      - T1566
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers frequently exploit Windows Explorer (explorer.exe) to execute malicious code due to its inherent trust within the operating system. This involves spawning child processes such as PowerShell, cmd.exe, or other scripting engines via Component Object Model (COM) and Distributed Component Object Model (DCOM). This technique enables attackers to bypass security controls, blending malicious activity with legitimate system processes. The detection rule identifies such anomalies by monitoring child processes of Explorer with specific characteristics, excluding known benign activities, to flag potential threats. This activity is frequently associated with initial access and execution of follow-on malware.

## Attack Chain

1.  The attack begins with an initial access vector such as spearphishing (T1566).
2.  A user clicks a malicious link or opens an attachment, leading to code execution.
3.  The initial payload exploits explorer.exe through DCOM using the -Embedding argument.
4.  Explorer.exe spawns a child process such as powershell.exe, cmd.exe, or mshta.exe (T1059, T1218).
5.  The spawned process executes malicious commands or scripts.
6.  These commands might download or execute additional payloads.
7.  The attacker achieves code execution, potentially gaining persistence on the system.
8.  The ultimate objective is often lateral movement, data exfiltration, or deploying ransomware.

## Impact

Successful exploitation allows attackers to execute arbitrary code within a trusted process context, bypassing application whitelisting and other security controls. This can lead to initial access, privilege escalation, and persistence within the compromised system. The compromise can remain undetected for extended periods due to the trusted nature of the parent process (explorer.exe), enabling attackers to perform reconnaissance, deploy malware, exfiltrate data, or disrupt services.

## Recommendation

*   Enable process creation logging with command line details to detect suspicious explorer.exe child processes.
*   Deploy the Sigma rule "Suspicious Explorer Child Process - PowerShell" to identify instances of PowerShell spawned by explorer.exe with suspicious arguments.
*   Deploy the Sigma rule "Suspicious Explorer Child Process - Scripting Engines" to detect other scripting engines launched by explorer.exe.
*   Monitor process execution events for processes like powershell.exe, cmd.exe, cscript.exe, wscript.exe, mshta.exe, regsvr32.exe, and rundll32.exe with a parent process of explorer.exe and the argument "-Embedding" via process creation logs.
*   Implement application control policies to restrict execution of unsigned or untrusted scripts and executables.
