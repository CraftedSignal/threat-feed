---
title: MsiExec Child Process Spawning Network Connections for Defense Evasion
slug: 2024-10-msiexec-network-connection
description: Detection of MsiExec spawning child processes that initiate network connections, potentially indicating abuse of Windows Installers for malware delivery and defense evasion.
date: "2024-10-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - msiexec
vendors:
  - Elastic
  - SentinelOne
  - Microsoft
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - Sysmon
  - Windows Installer
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_msiexec_child_proc_netcon.toml
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/007/
rules:
  - title: MsiExec Child Process with Unusual Executable and Network Connection
    description: Detects MsiExec spawning a child process with network connections where the child process executable is not a standard system executable.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
  - title: MsiExec Child Process DNS Request
    description: Detects a child process of msiexec.exe making DNS requests that are not typical
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1071.001
      - T1218.007
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

Adversaries may abuse the Windows Installer service (msiexec.exe) to proxy the execution of malicious payloads, effectively bypassing application control and other security mechanisms. This technique, known as "Msiexec" proxy execution (T1218.007), involves using msiexec.exe to execute malicious DLLs or scripts. The detection focuses on identifying child processes spawned by MsiExec, particularly those exhibiting network activity. This behavior is atypical for legitimate software installations and updates, making it a strong indicator of potential malicious use. Defenders should be aware of this technique as it allows attackers to blend in with legitimate system processes. The Elastic detection rule, updated on 2026-05-04, aims to identify this suspicious activity across multiple data sources including Elastic Defend, Sysmon, and SentinelOne.

## Attack Chain

1.  Attacker gains initial access to the system through an exploit or social engineering.
2.  Attacker leverages msiexec.exe to execute a malicious MSI package with a `/v` parameter, commonly used to pass verbose logging options, potentially hiding malicious commands.
3.  The malicious MSI package contains custom actions that execute arbitrary code.
4.  Msiexec.exe spawns a child process (e.g., powershell.exe, cmd.exe, or another executable) to carry out malicious actions.
5.  The child process establishes a network connection to an external server or performs DNS lookups, possibly for command and control (C2) communication or to download additional payloads.
6.  The attacker uses the network connection to download and execute further tools or scripts.
7.  The attacker performs lateral movement within the network.
8.  The final objective could be data exfiltration, ransomware deployment, or persistent access.

## Impact

Successful exploitation allows attackers to bypass application control and execute arbitrary code on the system. This can lead to malware installation, data theft, or complete system compromise. While the exact number of victims is not specified in the provided source, the technique can be applied across various sectors. The impact can range from individual workstation compromises to large-scale breaches affecting entire organizations.

## Recommendation

*   Deploy the Sigma rule `MsiExec Child Process with Unusual Executable and Network Connection` to detect suspicious msiexec.exe child processes initiating network connections based on unusual executable paths.
*   Enable Sysmon process creation logging (Event ID 1) and network connection logging (Event ID 3) to provide the necessary data for the Sigma rule.
*   Investigate any alerts triggered by the Sigma rules, focusing on the process tree, command-line arguments, and network destinations.
*   Review and whitelist legitimate software installations and automated deployment tools that use MsiExec and require network access to minimize false positives, as detailed in the "False positive analysis" section of the source material.
