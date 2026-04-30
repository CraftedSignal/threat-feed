---
title: Multiple Remote Management Tool Vendors on Same Host
slug: 2024-01-02-multiple-rmm-vendors
description: This detection identifies a Windows host where two or more distinct remote monitoring and management (RMM) or remote-access tool vendors are observed starting processes within the same eight-minute window, potentially indicating compromise, shadow IT, or attacker staging of redundant access.
date: "2024-01-02T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - command-and-control
  - rmm
  - windows
  - threat-detection
vendors:
  - AeroAdmin
  - AnyDesk
  - Atera
  - AweSun
  - APC
  - BeyondTrust
  - BarracudaRMM
  - Domotz
  - DWService
  - FleetDeck
  - GetScreen
  - GoTo
  - Impero
  - ISLOnline
  - JumpCloud
  - Level
  - LogMeIn
  - Lunixar
  - ManageEngine
  - MeshCentral
  - Mikogo
  - NinjaOne
  - Parsec
  - Pulseway
  - Radmin
  - RealVNC
  - RemotePC
  - Devolutions
  - RPCSuite
  - RustDesk
  - RemoteUtilities
  - Kaseya
  - ScreenConnect
  - Splashtop
  - Supremo
  - TacticalRMM
  - Tailscale
  - TeamViewer
  - Tiflux
  - ToDesk
  - Twingate
  - TightVNC
  - UltraVNC
  - UltraViewer
  - AnyAssist
  - Velociraptor
  - ToolsIQ
  - ZohoAssist
products:
  - AeroAdmin
  - AnyDesk
  - Atera Agent
  - AweSun
  - APC Admin
  - APC Host
  - BeyondTrust
  - Remote Support
  - BarracudaRMM
  - Domotz Agent
  - DWService
  - FleetDeck Commander
  - GetScreen
  - GoTo
  - Impero Client
  - Impero Server
  - ISLLight
  - ISLLightClient
  - JumpCloud Agent
  - Level
  - LvAgent
  - LogMeIn
  - Lunixar
  - ManageEngine Remote Access Plus
  - MeshAgent
  - Mikogo
  - NinjaRMMAgent
  - NinjaRMMAgenPatcher
  - ninjarmm-cli
  - Parsec
  - Pulseway
  - Radmin
  - RealVNC
  - RemotePC
  - RemoteDesktopManager
  - RPCSuite
  - RustDesk
  - RemoteUtilities
  - Kaseya
  - ScreenConnect
  - Splashtop
  - Supremo
  - SyncroLive
  - TacticalRMM
  - Tailscale
  - TeamViewer
  - Tiflux
  - ToDesk
  - Twingate
  - TightVNC
  - UltraVNC
  - UltraViewer
  - AnyAssist
  - Velociraptor
  - ToolsIQ
  - ZohoAssist
affected_os:
  - Windows
references:
  - https://attack.mitre.org/techniques/T1219/
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_multiple_rmm_vendors_same_host.toml
rules:
  - title: Multiple RMM Tools Execution on Same Host
    description: Detects the execution of multiple distinct RMM tools on the same host within a short timeframe, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1021.002
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Suspicious RMM Tool Installation Directory
    description: Detects RMM tool execution from non-standard directories, suggesting potential compromise.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Multiple RMM Tools Running with the Same Parent Process
    description: Detects when two or more distinct RMM tools are launched by the same parent process, suggesting potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection rule identifies Windows hosts running multiple remote monitoring and management (RMM) tools from different vendors within an eight-minute timeframe. While legitimate MSP environments may utilize multiple tools, this activity can also indicate malicious behavior, such as an attacker establishing redundant access to a compromised system. The rule maps various RMM processes to vendor labels, ensuring that multiple binaries from the same vendor do not inflate the count. The processes monitored include popular RMM tools like TeamViewer, AnyDesk, ScreenConnect, and many others. This rule is designed to detect suspicious activity within the environment and alert security teams to potential compromises. The timeframe is set to eight minutes to reduce false positives.

## Attack Chain

1. Initial Access: An attacker gains initial access to a Windows host, possibly through phishing or exploitation of a vulnerability.
2. Tool Deployment: The attacker deploys an initial RMM tool for remote access and control.
3. Secondary Tool Deployment: The attacker deploys a second RMM tool from a different vendor to ensure redundant access in case the first tool is detected or removed.
4. Privilege Escalation: The attacker escalates privileges to gain SYSTEM or Administrator rights, if necessary, to maintain persistent access and control.
5. Lateral Movement: The attacker uses the RMM tools to move laterally within the network to access additional systems and data.
6. Data Exfiltration/Malicious Activity: The attacker uses the established RMM connections to exfiltrate sensitive data or perform other malicious activities such as deploying ransomware.

## Impact

A successful attack can lead to unauthorized access to sensitive systems and data, potentially resulting in data breaches, financial loss, and reputational damage. This detection rule helps identify hosts that might be compromised by malicious actors utilizing multiple RMM tools for command and control. Identifying potentially compromised systems is key to preventing widespread damage.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM to detect multiple RMM tools running on the same host within an eight-minute window.
*   Investigate systems triggering this alert by reviewing process execution logs and network connections to identify the source of the RMM tool installation.
*   Enforce a policy of a single approved RMM stack per asset class to minimize the risk of unauthorized RMM tool usage.
*   Tune the provided Sigma rules with host or organizational unit exceptions for legitimate MSP/IT tooling environments.
*   Review asset inventory and change tickets for approved RMM software to identify unauthorized installations.
