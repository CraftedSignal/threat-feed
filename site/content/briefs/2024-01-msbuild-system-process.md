---
title: MSBuild Started by System Process
slug: 2024-01-msbuild-system-process
description: Detects instances of MSBuild, the Microsoft Build Engine, started by Explorer or the WMI (Windows Management Instrumentation) subsystem, which is unusual and often used by malicious payloads to evade defenses.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://attack.mitre.org/techniques/T1127/
  - https://attack.mitre.org/techniques/T1127/001/
  - https://attack.mitre.org/techniques/T1047/
rules:
  - title: Microsoft Build Engine Started by a System Process
    description: Detects MSBuild.exe started by explorer.exe or wmiprvse.exe, which is often indicative of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1047
      - T1127.001
    data_sources:
      - process_creation
      - windows
  - title: MSBuild Suspicious Command Line Arguments
    description: Detects suspicious command-line arguments used with MSBuild.exe.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1127.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Microsoft Build Engine (MSBuild) is a legitimate tool used for building applications, primarily by developers. However, attackers can abuse MSBuild to execute malicious code, taking advantage of its trusted status to bypass security measures. This detection identifies instances where MSBuild.exe is started by system processes like explorer.exe or wmiprvse.exe. This behavior is considered anomalous and may indicate an attempt to evade defenses and execute unauthorized actions on a Windows system. This activity can be indicative of defense evasion and execution-based attacks. The detection logic is based on process relationships, specifically monitoring MSBuild executions with unusual parent processes. The monitored processes include explorer.exe and wmiprvse.exe.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker uses a system process like `explorer.exe` or `wmiprvse.exe` as a launching point.
3.  The attacker crafts a malicious MSBuild project file (.csproj or similar) containing malicious code or instructions.
4.  The attacker invokes `MSBuild.exe` via `explorer.exe` or `wmiprvse.exe` to execute the crafted project file.
5.  `MSBuild.exe` parses and executes the malicious code within the project file.
6.  The malicious code performs actions such as downloading and executing payloads, modifying system configurations, or establishing persistence.
7.  The attacker achieves their objective, which may include escalating privileges, stealing credentials, or deploying ransomware.

## Impact

Successful exploitation can lead to code execution, privilege escalation, persistence, and ultimately, full system compromise. The attack is designed to evade traditional defenses by abusing a trusted system utility. The impact includes potential data theft, system disruption, or deployment of ransomware. This activity affects Windows systems and can bypass application control and other security measures relying on process whitelisting.

## Recommendation

*   Enable process monitoring with command-line auditing to detect the execution of `MSBuild.exe` with unusual parent processes (explorer.exe, wmiprvse.exe), as covered by the Sigma rule "Microsoft Build Engine Started by a System Process".
*   Investigate any instances of `MSBuild.exe` being launched by `explorer.exe` or `wmiprvse.exe`, as described in the overview.
*   Implement application control policies to restrict the execution of `MSBuild.exe` to authorized users and processes.
*   Monitor for suspicious command-line arguments passed to `MSBuild.exe` that could indicate malicious activity, based on the rule description.
