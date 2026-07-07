---
title: First Time Seen Remote Monitoring and Management Tool Detection
slug: 2026-07-first-seen-rmm
description: Adversaries are leveraging legitimate Remote Monitoring and Management (RMM) and remote access tools on Windows endpoints for command-and-control, persistence, and execution, with detection focusing on the first observed instance of these tools on a host.
date: "2026-07-03T15:36:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - persistence
  - execution
  - rmm
  - remote-access
  - windows
vendors:
  - Action1 Corporation
  - Aeroadmin LLC
  - AmidaWare LLC
  - Ammyy LLC
  - AnyDesk Software GmbH
  - AOMEI International Network Limited
  - Atera Networks Ltd
  - AWERAY PTE. LTD.
  - BeamYourScreen GmbH
  - Bomgar Corporation
  - BreakingSecurity.net
  - ConnectWise, Inc.
  - Devolutions Inc
  - DOMOTZ INC.
  - DUC FABULOUS CO.,LTD
  - DWSNET OÜ
  - Electronic Team, Inc.
  - Famatech Corp.
  - FleetDeck Inc
  - GlavSoft LLC
  - GoTo Technologies USA, LLC
  - Hefei Pingbo Network Technology Co. Ltd
  - IDrive, Inc.
  - Impero Solutions Limited
  - Instant Housecall
  - ISL Online Ltd.
  - JumpCloud Inc
  - Level Software, Inc.
  - LogMeIn, Inc.
  - LUNIXAR SAS DE CV
  - MMSOFT Design Ltd.
  - MSPBytes Corp
  - N-ABLE TECHNOLOGIES LTD
  - Nanosystems S.r.l.
  - NetSupport Ltd
  - NinjaOne LLC
  - NinjaRMM, LLC
  - Parallels International GmbH
  - philandro Software GmbH
  - Pro Softnet Corporation
  - PURSLANE
  - RealVNC Limited
  - REMOTE UTILITIES PTE. LTD.
  - Rocket Software, Inc.
  - Rsupport Co., Ltd.
  - SAFIB
  - Servably, Inc.
  - ShowMyPC INC
  - SimpleHelp Ltd
  - Splashtop Inc.
  - Superops Inc.
  - Tailscale Inc.
  - TeamViewer Germany GmbH
  - Techinline Limited
  - uvnc bvba
  - ZOHO Corporation Private Limited
products:
  - AA
  - Acronis Cyber Protect Connect Agent
  - AeroAdmin
  - AgentMon
  - AnyDesk
  - APC Admin
  - APC Host
  - AteraAgent
  - Aweray Remote
  - AweSun
  - B4-Service
  - BASupSrvc
  - Bomgar SCC
  - CagService
  - CloudRaCmd
  - CloudRaSd
  - CloudRaService
  - ConnectWise Control
  - Domotz Agent
  - DWSNET Agent
  - DameWare Remote Control
  - FleetDeck Commander
  - GetScreen
  - GoToAssist Service
  - GoTo Resolve
  - HelpWire
  - ImmyAgent
  - ImmyBot Agent Ephemeral
  - ImmyUpdater
  - Impero Client SVC
  - Impero Server SVC
  - ISL Light
  - ISL Light Client
  - JumpCloud Agent
  - Komari
  - Komari Agent
  - Level
  - LogMeIn Rescue
  - LogMeIn Ignition
  - LogMeIn
  - LTSvc
  - LTSvcMon
  - LTTray
  - Lunixar
  - Lunixar Remote
  - Lunixar Updater
  - LvAgent
  - ManageEngine Remote Access Plus
  - MeshAgent
  - Mikogo-Service
  - Nezha-agent
  - NinjaRMM Agent
  - NinjaRMM Agent Patcher
  - NinjaRMM CLI
  - Parsec
  - PService
  - Quick Assist
  - Radmin
  - RC EngMgr U
  - RCClient
  - RCMgrSVC
  - RCService
  - Remote Support
  - RemoteDesktopManager
  - Remotely Agent
  - Remotely Desktop
  - RemotePC
  - RemotePCDesktop
  - RemotePCService
  - RemoteView
  - RFUS Client
  - RMM Agent
  - ROMServer
  - ROMViewer
  - RPCSuite
  - RustDesk
  - RUTserv
  - RUTview
  - RV Agent
  - RV Agtray
  - SAAzAPSC
  - ScreenConnect
  - ScreenConnect Client Service
  - Session Win
  - SimpleGatewayService
  - SimpleHelp Customer
  - SMPC View
  - SPCLink
  - Splashtop Streamer
  - Splashtop SOS
  - SPSRV
  - SRAgent
  - SRService
  - SRManager
  - SRServer
  - STRWinClt
  - Supremo
  - SupremoService
  - Syncro App Runner
  - Syncro Installer
  - Syncro Overmind Service
  - Syncro Service
  - SyncroLive Agent
  - SyncroLive Agent Runner
  - SyncroLive Service
  - TacticalRMM
  - Tailscale
  - TeamViewer
  - TeamViewer Desktop
  - TeamViewer Service
  - TiAgent
  - TiClientCore
  - ToDesk Service
  - ToolsIQ
  - TSClient
  - TVN
  - TVNServer
  - TVNViewer
  - Twingate
  - UltraVNC
  - UltraViewer
  - Velociraptor
  - VNC Server
  - VNC Viewer
  - WinVNC
  - ZA Access
  - ZA Connect
  - Zaservice
  - ZMAgent
  - Zoho Meeting
  - ZohoURS
  - ZohoURSService
  - Zohotray
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Adversaries may install legitimate remote monitoring and management (RMM) tools or remote access software on compromised endpoints for command-and-control (C2), persistence, and execution of native commands.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Adversaries may install legitimate remote monitoring and management (RMM) tools or remote access software on compromised endpoints for command-and-control (C2), persistence, and execution of native commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Adversaries may install legitimate remote monitoring and management (RMM) tools or remote access software on compromised endpoints for command-and-control (C2), persistence, and execution of native commands.
    confidence_band: high
references:
  - https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
  - https://github.com/redcanaryco/surveyor/blob/master/definitions/remote-admin.json
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
  - https://www.cisa.gov/sites/default/files/2025-06/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf
  - https://lolrmm.io/
iocs:
  - type: url
    value: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
  - type: url
    value: https://github.com/redcanaryco/surveyor/blob/master/definitions/remote-admin.json
  - type: url
    value: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
  - type: url
    value: https://www.cisa.gov/sites/default/files/2025-06/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf
  - type: url
    value: https://lolrmm.io/
ioc_counts:
  url: 5
rules:
  - title: First Time Seen Remote Monitoring and Management Tool (Windows)
    description: Detects the first-time execution of legitimate remote monitoring and management (RMM) or remote access tools on Windows endpoints, which are commonly abused by adversaries for command-and-control, persistence, and execution.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
      - persistence
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Adversaries frequently exploit the trusted nature and broad capabilities of legitimate Remote Monitoring and Management (RMM) and remote access software to maintain covert access and control over compromised Windows systems. This threat brief focuses on the detection of these tools when they are observed for the first time on a given endpoint, indicating potential unauthorized deployment. While these tools are essential for IT administration, their abuse facilitates command-and-control (C2), enables persistence, and allows for the execution of arbitrary commands. Notable campaigns, such as those leading to domain-wide ransomware (as highlighted by The DFIR Report), often involve the misuse of RMM solutions like SimpleHelp, AnyDesk, and ConnectWise Control. This detection method identifies suspicious installations by monitoring process names and code signatures for commonly abused RMM tools, specifically triggering when a `host.id` and `process.name` pair has not been seen within a defined 7-day historical window.

## Attack Chain

1.  **Initial Access**: Adversaries gain initial access to an organization's network, often through methods such as phishing, exploiting vulnerable public-facing applications, or supply chain compromises.
2.  **Execution**: After establishing a foothold, the adversary deploys a legitimate RMM agent or client onto the compromised Windows host. This deployment may occur via various methods, including malicious ISO files (as referenced in a DFIR report) or existing remote access.
3.  **Persistence**: The installed RMM tool is configured by the adversary to ensure continued access to the compromised system, often by establishing itself as a service or through other autorun mechanisms.
4.  **Command and Control**: The RMM agent initiates an outbound connection to an adversary-controlled server, establishing a stable and often encrypted C2 channel that blends with legitimate network traffic.
5.  **Execution via RMM**: The adversary leverages the RMM tool's remote execution capabilities to deploy additional malware, execute commands, exfiltrate data, or initiate further lateral movement within the network.
6.  **Impact**: The adversary achieves their final objective, which can range from data exfiltration and espionage to the deployment of ransomware, encrypting critical organizational data.

## Impact

The abuse of RMM tools by adversaries can lead to severe organizational impact. When compromised, RMM tools provide a high level of control over the affected endpoints, enabling attackers to bypass traditional security controls due to the legitimate nature of the software. This can result in widespread data exfiltration, system damage through unauthorized software installations or configurations, and ultimately, significant financial losses due to ransomware deployment and business disruption. CISA has issued advisories highlighting the use of RMM tools in ransomware campaigns, underscoring the critical risk these compromises pose to organizations across all sectors.

## Recommendation

*   Deploy the provided Sigma rule "First Time Seen Remote Monitoring and Management Tool (Windows)" to your SIEM and tune it for your environment.
*   Ensure Sysmon process creation and code signing event logging is enabled across all Windows endpoints to provide the necessary telemetry for the detection rule.
*   Investigate all alerts generated by this rule immediately, focusing on the `process.executable`, `process.command_line`, and `process.code_signature.subject_name` fields.
*   Review network logs for suspicious outbound connections from newly observed RMM processes.
*   Establish clear organizational policies for RMM tool deployment and usage, including strict change management processes and whitelisting of authorized RMM executables and signers.
