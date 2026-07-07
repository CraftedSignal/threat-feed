---
title: 'Suspicious Activity: Multiple Remote Management Tool Vendors on Same Host'
slug: 2026-07-multiple-rmm-vendors-same-host
description: This brief describes a behavioral detection for Windows hosts where two or more distinct remote monitoring and management (RMM) or remote-access tools from different vendors are observed starting processes within an eight-minute window, indicating potential compromise, shadow IT, or attacker staging of redundant access.
date: "2026-07-03T15:47:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - remote-access-software
  - rmm
  - windows
  - behavioral-detection
vendors:
  - Acronis
  - AeroAdmin
  - American Power Conversion
  - AnyDesk
  - AnyAssist
  - Atera
  - AweSun
  - Barracuda Networks
  - BeyondTrust
  - CloudRadial
  - ConnectWise
  - Devolutions
  - Domotz
  - DWService
  - Famatech
  - FleetDeck
  - GetScreen
  - GoTo
  - HelpWire
  - ImmyBot
  - Impero
  - ISL Online
  - JumpCloud
  - Kaseya
  - Komari
  - Level
  - LogMeIn
  - Lunixar
  - ManageEngine
  - MeshCentral
  - Microsoft
  - Mikogo
  - Nezha
  - NinjaOne
  - Parsec
  - Pulseway
  - RealVNC
  - Remotely
  - RemotePC
  - Remote Utilities
  - RPCSuite
  - Rsupport
  - RustDesk
  - SimpleHelp
  - Splashtop
  - SuperOps
  - Supremo
  - TacticalRMM
  - Tailscale
  - Zoho
products:
  - Acronis Cyber Protect Connect
  - AeroAdmin
  - APC Remote Management
  - AnyDesk
  - AnyAssist
  - Atera RMM
  - AweSun Remote Desktop
  - Barracuda RMM
  - BeyondTrust Remote Support
  - CloudRadial
  - ConnectWise Automate
  - ConnectWise Control
  - Devolutions Remote Desktop Manager
  - Domotz RMM
  - DWService
  - FleetDeck Commander
  - GetScreen
  - GoTo
  - HelpWire
  - ImmyBot RMM
  - Impero
  - ISL Online
  - JumpCloud Agent
  - Kaseya VSA
  - Komari
  - Level.io
  - LogMeIn
  - Lunixar Remote
  - ManageEngine Remote Access Plus
  - MeshCentral
  - Microsoft Quick Assist
  - Mikogo
  - Nezha Agent
  - NinjaOne RMM
  - Parsec
  - Pulseway RMM
  - Radmin
  - RealVNC
  - Remotely
  - RemotePC
  - Remote Utilities
  - RPCSuite
  - Rsupport RemoteView
  - RustDesk
  - SimpleHelp
  - Splashtop
  - SuperOps RMM
  - Supremo Remote Desktop
  - TacticalRMM
  - Tailscale
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Identifies a Windows host where two or more distinct remote monitoring and management (RMM) or remote-access tool vendors are observed starting processes within the same eight-minute window.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1219/
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
  - https://lolrmm.io/
---

This detection rule identifies a suspicious behavioral pattern on Windows hosts where processes associated with two or more distinct remote monitoring and management (RMM) or remote-access tool vendors are observed initiating within the same eight-minute window. This activity is considered suspicious because it can indicate unauthorized activity, such as an attacker establishing redundant persistence and command and control, the presence of shadow IT, or a potential system compromise. While some legitimate Managed Service Provider (MSP) environments might use multiple tools (e.g., ConnectWise Automate and TeamViewer), this pattern on standard user endpoints or servers warrants immediate investigation. The detection mechanism specifically maps known RMM process names to unique vendor labels (e.g., AnyDesk, Splashtop, NinjaOne), preventing false positives from multiple binaries of the same vendor. This detection helps security teams identify anomalous RMM usage, which is a common tactic for initial access brokers and post-exploitation activities.

## Attack Chain

This detection focuses on identifying suspicious activity rather than a specific multi-stage attack chain. The presence of multiple RMM tools from distinct vendors typically occurs during the post-compromise phase, as attackers establish persistence and redundant command and control.

## Impact

If not investigated and addressed, the presence of multiple, potentially unauthorized, remote management tools can lead to severe consequences. Attackers often deploy additional RMM tools to maintain persistence and establish redundant command and control channels, even after their primary access might be remediated. This increases the risk of data exfiltration, further lateral movement, deployment of ransomware, and long-term compromise of the affected host and wider network. Uncontrolled RMM installations also present a significant attack surface due to their elevated privileges and network access capabilities, making the host a critical pivot point for further malicious activities.

## Recommendation

*   Deploy the described detection logic to identify hosts exhibiting simultaneous process execution from multiple RMM vendors.
*   Enable Sysmon Event ID 1 (Process Creation) and Windows process creation logging across your environment to ensure comprehensive coverage for process start events.
*   Investigate alerts related to MITRE ATT&CK technique T1219 (Remote Access Software) to determine legitimacy.
*   For hosts triggering this detection, immediately investigate the Esql.vendors_seen and Esql.processes_executable_values fields to identify the specific tools involved.
*   For servers or standard user endpoints, treat such alerts as high risk; review install sources, code signatures, and recent logons for the involved processes.
*   Correlate alerts with other suspicious activities (e.g., ingress tool transfer, suspicious scripting, new persistence mechanisms) on the same host.
*   Establish and enforce a clear policy for approved RMM software, ideally limiting to a single approved stack per asset class to reduce false positives and attack surface.
