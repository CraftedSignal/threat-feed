---
title: Detection of Kali Linux Installation or Usage via Windows Subsystem for Linux (WSL)
slug: 2024-01-kali-wsl-install
description: Adversaries may attempt to install or use Kali Linux via Windows Subsystem for Linux (WSL) to avoid detection, potentially enabling them to perform malicious activities within a Windows environment while blending in with legitimate WSL usage.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - wsl
  - kalilinux
vendors:
  - Microsoft
  - SentinelOne
  - Crowdstrike
  - Elastic
products:
  - Windows Subsystem for Linux
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Elastic Defend
  - Elastic Endpoint Security
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/windows/wsl/basic-commands
  - https://learn.microsoft.com/en-us/windows/wsl/wsl-config
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_wsl_kalilinux.toml
rules:
  - title: Detect Kali Linux Installation via WSL
    description: Detects the installation of Kali Linux via Windows Subsystem for Linux (WSL) by monitoring the wsl.exe process with specific arguments.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - process_creation
      - windows
  - title: Detect Kali Linux Executable via WSL
    description: Detects the execution of the Kali Linux executable (kali.exe) within the Windows Subsystem for Linux (WSL) environment.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies attempts to install or utilize Kali Linux through the Windows Subsystem for Linux (WSL). Attackers may leverage WSL to deploy Kali Linux as a means of circumventing traditional security measures and carrying out malicious operations within a Windows operating system. This behavior enables them to potentially blend their activities with legitimate WSL usage, making detection more challenging. The detection focuses on identifying specific processes and command-line arguments associated with Kali Linux installations and executions within the WSL environment, aiming to expose malicious actors utilizing this technique for nefarious purposes. This activity started being tracked in early 2023. Defenders should be aware of this technique, as it can be used to bypass security controls and perform malicious activities discreetly.

## Attack Chain

1.  An attacker gains initial access to a Windows system through methods outside the scope of this specific detection (e.g., phishing, exploitation of a vulnerability).
2.  The attacker enables WSL on the target Windows system using PowerShell or command-line tools.
3.  The attacker downloads the Kali Linux distribution for WSL from the Microsoft Store or another source.
4.  The attacker uses `wsl.exe` with arguments like `-d`, `--distribution`, `-i`, or `--install` along with "kali*" to install the Kali Linux distribution.
5.  Alternatively, the attacker directly executes the `kali.exe` binary located within the Kali Linux package path (e.g., `C:\\Users\\*\\AppData\\Local\\packages\\kalilinux*`).
6.  Once Kali Linux is installed, the attacker uses it to perform various malicious activities, such as penetration testing, vulnerability scanning, or exploiting other systems on the network.
7.  The attacker may leverage tools and utilities within Kali Linux to escalate privileges, move laterally, or exfiltrate sensitive data.
8.  The final objective is typically to compromise the target system or network, steal valuable information, or disrupt operations.

## Impact

A successful attack using Kali Linux within WSL can lead to significant damage, including data breaches, system compromise, and disruption of services. The use of Kali Linux provides attackers with a wide range of tools and capabilities for reconnaissance, exploitation, and post-exploitation activities. Depending on the attacker's objectives, this can result in financial losses, reputational damage, and legal liabilities. Organizations across various sectors are vulnerable, as this technique can be used against any Windows system with WSL enabled.

## Recommendation

*   Deploy the Sigma rule "Detect Kali Linux Installation via WSL" to your SIEM to detect the use of `wsl.exe` with specific Kali Linux installation arguments (rule).
*   Deploy the Sigma rule "Detect Kali Linux Executable via WSL" to your SIEM to detect the direct execution of `kali.exe` from the common install directories (rule).
*   Monitor process creation events for the execution of `wsl.exe` and `kali.exe` within the Windows environment (logsource).
*   Review and restrict the usage of WSL within the organization to only authorized users and systems (overview).
*   Implement application control policies to prevent the execution of unauthorized binaries, including `kali.exe` (overview).
