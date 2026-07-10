---
title: Windows Subsystem for Linux Distribution Installation via Registry Modification
slug: 2024-01-wsl-registry-install
description: Detects the installation of a new Windows Subsystem for Linux (WSL) distribution through registry modifications, which can be leveraged by attackers to evade security measures and execute malicious activities on Windows systems.
date: "2024-01-09T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - windows
  - wsl
vendors:
  - Microsoft
products:
  - Windows Subsystem for Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://learn.microsoft.com/en-us/windows/wsl/wsl-config
rules:
  - title: Windows Subsystem for Linux Distribution Installed
    description: Detects changes to the registry indicating the installation of a new Windows Subsystem for Linux distribution by name.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: WSL Enabled via Dism Utility
    description: Detects when the Windows Subsystem for Linux is enabled via the DISM utility.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1112
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows Subsystem for Linux (WSL) allows developers to run Linux distributions directly on Windows. Adversaries may abuse WSL to evade security protections and perform various attacks. This rule detects the installation of a new WSL distribution by monitoring registry changes. The rule focuses on changes in the registry indicating the installation of a new WSL distribution, which is identified by modifications to the `PackageFamilyName` key under the `SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\` path. The modification of this registry key is a key indicator that a new WSL distribution has been installed. Detecting this activity allows security teams to identify potentially malicious use of WSL for Linux in their environment.

## Attack Chain

1. An attacker gains initial access to a Windows system through various means (e.g., phishing, exploiting a vulnerability).
2. The attacker executes commands to enable the Windows Subsystem for Linux feature, if not already enabled.
3. The attacker downloads and installs a Linux distribution (e.g., Ubuntu, Kali) through the Microsoft Store or using command-line tools such as `wsl.exe --install`.
4. The installation process modifies the Windows registry, specifically creating or modifying keys under `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss`.
5. The `PackageFamilyName` value under the distribution-specific subkey is set to identify the installed Linux distribution.
6. The attacker uses the installed WSL distribution to execute Linux-based tools and scripts, potentially for reconnaissance, privilege escalation, or lateral movement.
7. The attacker leverages the WSL environment to bypass Windows security controls and execute malicious payloads.

## Impact

A successful attack using WSL can lead to various consequences, including the installation of unauthorized software, execution of malicious code, and potential compromise of sensitive data. WSL can be used to mask malicious activity, making it harder to detect. If an attacker successfully installs and uses WSL, they may be able to bypass existing security controls and compromise the system.

## Recommendation

*   Enable Sysmon registry event logging to monitor registry modifications (Data Source: Sysmon).
*   Deploy the Sigma rule "Windows Subsystem for Linux Distribution Installed" to detect WSL distribution installations via registry modifications.
*   Investigate any detected installations of WSL distributions, especially if the user account performing the installation is not authorized to do so (Sigma rule).
*   Monitor for unusual network activity originating from WSL instances (references, https://learn.microsoft.com/en-us/windows/wsl/wsl-config).
