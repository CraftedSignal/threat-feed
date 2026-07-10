---
title: Excel Spawning Uncommon Microsoft Applications
slug: 2024-01-excel-spawning-uncommon-apps
description: Microsoft Excel spawning uncommon Microsoft application executables like WINPROJ.EXE, FOXPROW.exe, or SCHDPLUS.exe is anomalous and may indicate malicious activity, such as malware execution, persistence mechanisms, or command-and-control attempts.
date: "2024-01-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - execution
  - initial-access
  - windows
vendors:
  - Microsoft
products:
  - Microsoft Excel
  - Microsoft Project
  - Visual FoxPro
  - Microsoft Schedule+
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/
  - https://blog.talosintelligence.com/pathwiper-targets-ukraine/
  - https://www.trellix.com/blogs/research/dcom-abuse-and-network-erasure-with-trellix-ndr/
rules:
  - title: Excel Spawning Microsoft Project
    description: Detects Excel spawning Microsoft Project (WINPROJ.EXE) as a child process, which is an unusual activity.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.003
    data_sources:
      - process_creation
      - windows
  - title: Excel Spawning Visual FoxPro
    description: Detects Excel spawning Visual FoxPro (FOXPROW.EXE) as a child process, which is an unusual activity.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.003
    data_sources:
      - process_creation
      - windows
  - title: 'Excel Spawning Microsoft Schedule+ '
    description: Detects Excel spawning Microsoft Schedule+ (SCHDPLUS.EXE) as a child process, which is an unusual activity.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.003
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This brief focuses on the unusual behavior of Microsoft Excel spawning uncommon Microsoft application executables. Typically, Excel spawns internal Office-related processes. The execution of executables such as WINPROJ.EXE (Microsoft Project), FOXPROW.exe (Visual FoxPro), or SCHDPLUS.exe (Microsoft Schedule+) as child processes of Excel is uncommon in typical business workflows. Adversaries may exploit this behavior to disguise malicious activity, execute unauthorized code, or bypass application control measures. This tactic is relevant because Office applications are often leveraged as initial access or execution vectors due to their prevalence in enterprise environments. Detecting this parent-child process relationship can help identify suspicious behavior that may indicate malware execution, persistence mechanisms, or command and control activities.

## Attack Chain

1.  The attacker gains initial access, potentially through phishing or exploiting a vulnerability, to execute code within a trusted context like Microsoft Excel.
2.  The attacker leverages Excel's capabilities (e.g., macros, DDE) to execute a command.
3.  The command initiates the creation of an unusual child process.
4.  Excel spawns WINPROJ.EXE, FOXPROW.exe, or SCHDPLUS.exe. This can be achieved using techniques like `ActivateMicrosoftApp()`.
5.  The spawned process (e.g., WINPROJ.EXE) executes further malicious code.
6.  This code could download additional payloads, establish persistence, or perform lateral movement within the network.
7.  The attacker may attempt to blend the activity by leveraging legitimate Microsoft processes.
8.  The final objective is to achieve command and control, data exfiltration, or deploy ransomware.

## Impact

Successful exploitation can lead to the execution of arbitrary code, data theft, and system compromise. While the exact number of affected organizations is unknown, this technique can be used to target organizations of any size. The impact includes potential data breaches, financial losses, reputational damage, and disruption of normal business operations. As Microsoft Project (WINPROJ.EXE), Visual FoxPro (FOXPROW.exe), and Microsoft Schedule+ (SCHDPLUS.exe) are not commonly used, their presence as a child process of Excel is highly suspicious.

## Recommendation

*   Enable Sysmon process creation logging (Event ID 1) and Windows Event Log Security (Event ID 4688) to capture process creation events, a requirement for the Sigma rules.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect the anomalous parent-child process relationships.
*   Investigate any instances where Excel spawns WINPROJ.EXE, FOXPROW.exe, or SCHDPLUS.exe, focusing on the context of the Excel process, command-line arguments, and subsequent network or file activity.
*   Implement application control policies to restrict the execution of unauthorized or uncommon applications.
*   Monitor network connections originating from WINPROJ.EXE, FOXPROW.exe, or SCHDPLUS.exe for suspicious traffic patterns.
