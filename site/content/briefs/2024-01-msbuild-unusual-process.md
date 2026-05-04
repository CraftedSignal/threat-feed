---
title: MSBuild запускает необычные процессы
slug: 2024-01-msbuild-unusual-process
description: Adversaries may exploit MSBuild to execute malicious scripts or compile code, bypassing security controls; this rule detects unusual processes initiated by MSBuild, such as PowerShell or C# compiler, signaling potential misuse for executing unauthorized or harmful actions.
date: "2024-01-03T15:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - msbuild
vendors:
  - Microsoft
  - Elastic
products:
  - MSBuild
  - Elastic Defend
  - Sysmon
  - Windows Security Event Logs
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://blog.talosintelligence.com/2020/02/building-bypass-with-msbuild.html
rules:
  - title: Microsoft Build Engine Started PowerShell
    description: Detects instances where MSBuild spawns PowerShell, which could indicate malicious payload deployment or script execution.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
      - T1127.001
    data_sources:
      - process_creation
      - windows
  - title: Microsoft Build Engine Started CSharp Compiler
    description: Detects instances where MSBuild spawns the C# compiler (csc.exe), potentially indicating malicious code compilation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.004
      - T1127.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Microsoft Build Engine (MSBuild) is a legitimate tool used for building applications. However, adversaries may abuse MSBuild to execute malicious scripts or compile code, effectively bypassing security controls. This technique is often employed to deploy malicious payloads. This detection focuses on identifying instances where MSBuild initiates unusual processes such as PowerShell, Internet Explorer, or the Visual C# Command Line Compiler (csc.exe). This activity is considered suspicious because legitimate software development workflows do not typically involve MSBuild directly spawning these processes. The original Elastic detection rule was created on 2020-03-25 and last updated on 2026-05-04.

## Attack Chain

1. An attacker gains initial access to a system (e.g., through phishing or exploiting a vulnerability).
2. The attacker modifies or creates an MSBuild project file (.csproj or .sln) containing malicious commands.
3. The malicious MSBuild project file is crafted to execute a script or compile code.
4. The attacker uses the MSBuild.exe or msbuild.exe utility to execute the malicious project file.
5. MSBuild spawns an unusual process such as powershell.exe, csc.exe, or iexplore.exe based on the malicious project file configuration.
6. PowerShell executes arbitrary commands, downloads further payloads, or performs other malicious actions.
7. The C# compiler (csc.exe) compiles malicious code into an executable or library.
8. The compiled malware or downloaded payloads execute, leading to further compromise, such as data exfiltration or lateral movement.

## Impact

Successful exploitation can lead to arbitrary code execution, allowing attackers to deploy malware, compromise sensitive data, and establish persistence on the targeted system. The use of MSBuild for malicious purposes allows attackers to bypass application whitelisting and other security controls that trust signed Microsoft binaries. While the precise number of victims is unknown, this technique can be employed against a wide range of organizations, particularly those with vulnerable systems or inadequate endpoint protection.

## Recommendation

*   Enable process creation logging, specifically including parent-child relationships, to detect unusual process spawning by MSBuild (logs-endpoint.events.process-\*, logs-system.security\*, logs-windows.forwarded\*, logs-windows.sysmon_operational-\*, winlogbeat-\*).
*   Deploy the Sigma rule "Microsoft Build Engine Started an Unusual Process" to your SIEM to identify instances of MSBuild spawning suspicious processes, and tune for your environment.
*   Investigate any instances of MSBuild spawning PowerShell, csc.exe, or iexplore.exe to determine if the activity is legitimate or malicious (process.name:("csc.exe" or "iexplore.exe" or "powershell.exe")).
*   Monitor for modifications to MSBuild project files (.proj or .sln) for signs of tampering.
