---
title: Image File Execution Options (IFEO) Injection for Persistence and Defense Evasion
slug: 2024-01-ifeo-injection
description: Attackers can establish persistence and evade defenses by modifying the Debugger and SilentProcessExit registry keys to perform Image File Execution Options (IFEO) injection, allowing them to intercept file executions and run malicious code.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - registry
  - ifeo
  - windows
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
  - Crowdstrike
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - CrowdStrike FDR
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
rules:
  - title: Detect Image File Execution Options Injection
    description: Detects changes to the Debugger registry key used for IFEO injection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1546.012
    data_sources:
      - registry_set
      - windows
  - title: Detect SilentProcessExit MonitorProcess Modification
    description: Detects changes to the MonitorProcess registry key under SilentProcessExit, indicating potential IFEO injection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1546.012
    data_sources:
      - registry_set
      - windows
  - title: Detect IFEO Injection via Registry Data Strings
    description: Detects IFEO injection by monitoring registry data strings for suspicious executable paths.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1546.012
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

Image File Execution Options (IFEO) injection is a Windows feature that allows developers to debug applications by specifying an alternative executable to run. Attackers abuse this feature by modifying the Debugger and SilentProcessExit registry keys, setting a debugger to execute malicious code instead of the intended application. This technique is used to establish persistence or evade defenses. The attack involves modifying registry keys under `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options`, `HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options`, `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit`, and `HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit`. This matters to defenders because successful IFEO injection can allow attackers to maintain persistent access to a system and execute malicious code without detection.

## Attack Chain

1.  The attacker gains initial access to the system through unspecified means (e.g., exploiting a vulnerability or using stolen credentials).
2.  The attacker elevates privileges to gain administrative access, allowing modification of sensitive registry keys.
3.  The attacker modifies the registry, specifically the `Debugger` or `MonitorProcess` values within the IFEO or SilentProcessExit keys for a target executable (e.g., `notepad.exe`).
4.  The `Debugger` or `MonitorProcess` value is set to point to a malicious executable.
5.  When the target executable is launched by a user or system process, the malicious executable is launched instead.
6.  The malicious executable performs its intended actions, such as installing malware, stealing credentials, or establishing a reverse shell.
7.  The attacker maintains persistence through the IFEO injection, as the malicious executable will continue to be launched whenever the target executable is run.

## Impact

Successful IFEO injection can allow attackers to maintain persistent access to a system, execute malicious code without detection, and potentially compromise sensitive data. IFEO injection can lead to a full compromise of the affected system, potentially impacting all users and applications on the system. This technique is often used in conjunction with other attack methods to achieve broader objectives, such as data exfiltration or ransomware deployment.

## Recommendation

*   Enable Windows Registry auditing to monitor changes to the IFEO and SilentProcessExit registry keys, enabling detection of unauthorized modifications.
*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious registry modifications related to IFEO injection.
*   Review and update the exceptions list in the Sigma rules to account for legitimate uses of the Debugger and MonitorProcess registry keys, reducing false positives.
*   Monitor process execution and correlate with registry modifications to identify potentially malicious processes launched via IFEO injection.
*   Implement enhanced monitoring and logging for registry changes related to IFEO to detect and respond to similar threats in the future.
