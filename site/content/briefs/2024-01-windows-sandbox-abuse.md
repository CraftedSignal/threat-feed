---
title: Windows Sandbox Abuse with Sensitive Configuration
slug: 2024-01-windows-sandbox-abuse
description: This rule detects the abuse of Windows Sandbox with sensitive configurations to evade detection, where malware may abuse the sandbox feature to gain write access to the host file system, enable network connections, and automatically execute commands via logon, identifying the start of a new container with these sensitive configurations.
date: "2024-01-10T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows-sandbox
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - CrowdStrike FDR
  - Sysmon
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
references:
  - https://blog-en.itochuci.co.jp/entry/2025/03/12/140000
  - https://attack.mitre.org/techniques/T1564/
  - https://attack.mitre.org/techniques/T1564/006/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Windows Sandbox with Host Folder Access
    description: Detects Windows Sandbox processes with configuration allowing write access to host folders, potentially used for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1564.006
    data_sources:
      - process_creation
      - windows
  - title: Windows Sandbox with Networking Enabled
    description: Detects Windows Sandbox processes with network access enabled.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1564.006
    data_sources:
      - process_creation
      - windows
  - title: Windows Sandbox with Logon Command
    description: Detects Windows Sandbox processes using LogonCommand to execute commands on startup.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1564.006
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers may abuse the Windows Sandbox feature to evade detection by running malicious code within the isolated environment. This involves configuring the sandbox with sensitive options such as granting write access to the host file system, enabling network connections, and setting up automatic command execution via logon. By running within the sandbox with these configurations, malware can potentially interact with the host system, while making detection more difficult. This technique is used for defense evasion, hiding artifacts, and executing malicious activities within a virtualized environment to avoid direct exposure on the host. The rule identifies the start of a new container with sensitive configurations like write access to the host file system, network connection and automatic execution via logon command.

## Attack Chain

1. An attacker gains initial access to the system through an exploit or social engineering.
2. The attacker leverages Windows Sandbox by executing `wsb.exe` or `WindowsSandboxClient.exe`.
3. The attacker configures the sandbox to enable networking using `<Networking>Enable</Networking>` or `<NetworkingEnabled>true</NetworkingEnabled>`.
4. The attacker grants the sandbox write access to the host file system using `<HostFolder>C:\\<ReadOnly>false`.
5. The attacker sets up a logon command to automatically execute malicious code when the sandbox starts using `<LogonCommand>`.
6. The sandbox initializes and executes the configured logon command.
7. The malicious code interacts with the host file system and network, performing actions such as data exfiltration or lateral movement.
8. The attacker achieves their objective, such as deploying ransomware or stealing sensitive information, while operating from within the isolated sandbox environment.

## Impact

A successful attack using Windows Sandbox abuse can lead to a range of negative impacts. Attackers may gain unauthorized access to sensitive data, compromise system integrity, or disrupt business operations. The use of the sandbox environment helps to conceal malicious activity, making detection and remediation more challenging. The damage can include data breaches, financial losses, reputational damage, and regulatory penalties. Successful exploitation allows malware to interact with the host system, potentially affecting multiple systems on the network.

## Recommendation

*   Deploy the "Windows Sandbox with Sensitive Configuration" detection rule to your SIEM to identify potential sandbox abuse attempts.
*   Monitor process creation events for `wsb.exe` and `WindowsSandboxClient.exe` with command-line arguments that enable networking (`<Networking>Enable</Networking>`, `<NetworkingEnabled>true</NetworkingEnabled>`).
*   Monitor process creation events for `wsb.exe` and `WindowsSandboxClient.exe` with command-line arguments that enable write access to the host file system (`<HostFolder>C:\\<ReadOnly>false`).
*   Monitor process creation events for `wsb.exe` and `WindowsSandboxClient.exe` with command-line arguments that define logon commands (`<LogonCommand>`).
*   Enable Sysmon process creation logging (Event ID 1) to capture the necessary command-line arguments.
