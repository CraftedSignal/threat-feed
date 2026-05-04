---
title: Multiple Remote Management Tool Vendors on Same Host
slug: 2024-01-multiple-rmm-vendors
description: This rule identifies Windows hosts where two or more distinct remote monitoring and management (RMM) or remote-access tool vendors are observed starting processes within the same eight-minute window, potentially indicating compromise, shadow IT, or attacker staging of redundant access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - remote-access-tool
  - command-and-control
  - rmm
  - windows
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
  - AteraAgent
  - AweSun
  - APC Admin
  - APC Host
  - BeyondTrust Remote Support
  - Bomgar
  - Remote Support
  - B4-Service
  - CagService
  - Domotz Agent
  - dwagsvc
  - DWRCC
  - FleetDeck Commander
  - GetScreen
  - GoToAssist
  - GoToResolve
  - ImperoClient
  - ImperoServer
  - ISLLight
  - ISLLightClient
  - JumpCloud Agent
  - Level
  - LvAgent
  - LMIIgnition
  - LogMeIn
  - Lunixar
  - ManageEngine Remote Access Plus
  - MeshAgent
  - Mikogo
  - NinjaRMM
  - parsec
  - PService
  - Radmin
  - RealVNC
  - RemotePC
  - RemoteDesktopManager
  - RCClient
  - RCService
  - RPCSuite
  - RustDesk
  - RemoteUtilities
  - saazapsc
  - ScreenConnect
  - Splashtop
  - Supremo
  - Syncro
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
rules:
  - title: Multiple RMM Tools Process Creation
    description: Detects the execution of multiple RMM tools from different vendors on the same host by monitoring process creation events. This activity can indicate unauthorized access or attacker staging.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Detect Multiple Splashtop RMM Executables
    description: Detects the execution of Splashtop RMM executables on a system, which can indicate legitimate use or malicious activity related to remote access.
    platform: sigma
    severity: informational
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies Windows systems running multiple Remote Monitoring and Management (RMM) tools from different vendors within an eight-minute timeframe. While legitimate MSP environments might utilize several tools, the presence of multiple RMM solutions on a single host can signify a compromise, unauthorized software installation (shadow IT), or attackers establishing redundant access points. The rule maps process names to vendor labels to avoid inflated counts from multiple binaries of the same vendor. This activity has been observed as a component of broader attack campaigns, including those leveraging compromised MSP infrastructure, and is described in CISA AA23-025A. The timeframe analyzed is "now-9m", and the rule triggers if two or more different vendors are detected.

## Attack Chain

1. Initial Access: The attacker gains initial access to the system, possibly through phishing, exploiting vulnerabilities, or stolen credentials.
2. Tool Deployment: The attacker deploys an initial RMM tool (e.g., AnyDesk, TeamViewer) for remote access and control.
3. Persistence: The attacker establishes persistence by configuring the RMM tool to start automatically on system boot.
4. Lateral Movement: The attacker uses the initial access to discover other systems on the network.
5. Additional RMM Deployment: The attacker deploys a second RMM tool (e.g., ScreenConnect, Splashtop) from a different vendor to create a redundant access method.
6. Privilege Escalation: The attacker escalates privileges using the compromised RMM tools, if necessary.
7. Remote Control: The attacker uses the RMM tools to remotely control the system, execute commands, and access sensitive data.
8. Data Exfiltration or Further Exploitation: The attacker exfiltrates sensitive data or uses the compromised system to launch further attacks on the network.

## Impact

A successful attack leveraging multiple RMM tools can result in unauthorized access to sensitive data, system compromise, and lateral movement within the network. The presence of multiple RMM tools increases the attacker's resilience, making it harder to detect and remediate the intrusion. Affected systems can be used as a staging ground for further attacks, leading to significant financial and reputational damage. This can impact any Windows-based system, and the CISA advisory AA23-025A specifically highlights the risk of MSP infrastructure compromise.

## Recommendation

*   Deploy the Sigma rule `Multiple RMM Vendors on Same Host` to your SIEM and tune for your environment.
*   Investigate hosts triggering the rule to confirm legitimate use of multiple RMM tools. Check `Esql.vendors_seen` and `Esql.processes_name_values` for insight into the involved tools.
*   Review asset inventory and change tickets to verify authorized RMM software installations.
*   Isolate any unauthorized or unexplained hosts and remove unapproved RMM tools.
*   Enforce a single approved RMM stack per asset class where possible.
*   Enable Sysmon process creation logging (Event ID 1) on Windows endpoints to enhance detection capabilities as described in the rule's setup instructions.
