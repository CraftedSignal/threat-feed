---
title: First Time Seen Remote Monitoring and Management Tool Usage
slug: 2024-01-first-time-seen-rmm
description: This rule detects the first time a remote monitoring and management (RMM) or remote access process is seen on a host within a defined history window, indicating potential command-and-control, persistence, or unauthorized remote access activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - rmm
  - remote_access
  - command_and_control
vendors:
  - Action1 Corporation
  - AeroAdmin LLC
  - Ammyy LLC
  - Atera Networks Ltd
  - AWERAY PTE. LTD.
  - BeamYourScreen GmbH
  - Bomgar Corporation
  - DUC FABULOUS CO.,LTD
  - DOMOTZ INC.
  - DWSNET OÜ
  - FleetDeck Inc
  - GlavSoft LLC
  - Hefei Pingbo Network Technology Co. Ltd
  - IDrive, Inc.
  - IMPERO SOLUTIONS LIMITED
  - Instant Housecall
  - ISL Online Ltd.
  - LogMeIn, Inc.
  - LUNIXAR SAS DE CV
  - MMSOFT Design Ltd.
  - Nanosystems S.r.l.
  - NetSupport Ltd
  - NinjaRMM, LLC
  - Parallels International GmbH
  - philandro Software GmbH
  - Pro Softnet Corporation
  - RealVNC
  - Remote Utilities LLC
  - Rocket Software, Inc.
  - SAFIB
  - Servably, Inc.
  - ShowMyPC INC
  - Splashtop Inc.
  - Superops Inc.
  - TeamViewer
  - Techinline Limited
  - uvnc bvba
  - Yakhnovets Denis Aleksandrovich IP
  - ZOHO Corporation Private Limited
  - Connectwise, LLC
  - BreakingSecurity.net
products:
  - ScreenConnect Client
  - Action1 Corporation
  - AeroAdmin LLC
  - Ammyy LLC
  - AteraAgent.exe
  - AWERAY Remote
  - AweSun.exe
  - Bomgar Corporation
  - Domotz Agent
  - DWSNET
  - FleetDeck Commander
  - IDrive
  - IMPERO
  - Instant Housecall
  - ISL Online
  - LogMeIn, Inc.
  - Lunixar
  - MeshAgent.exe
  - NinjaRMM Agent
  - Parsec
  - Quick Assist
  - Radmin
  - Remote Desktop Manager
  - RemotePC
  - Remote Utilities
  - RustDesk
  - ScreenConnect
  - Splashtop
  - Superops
  - TeamViewer
  - Techinline
  - UltraVNC
  - UltraViewer
  - VNC
  - ZohoURS.exe
  - Velociraptor.exe
  - GoToResolve
  - Tailscale
  - Syncro
  - Connectwise ScreenConnect
  - Atera Networks Ltd
affected_os:
  - Windows
references:
  - https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
  - https://attack.mitre.org/techniques/T1219/002/
  - https://github.com/redcanaryco/surveyor/blob/master/definitions/remote-admin.json
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
  - https://www.cisa.gov/sites/default/files/2025-06/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf
rules:
  - title: RMM Tool Process Execution
    description: Detects execution of known RMM tools by monitoring process names.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - process_creation
      - windows
  - title: RMM Tool Code Signature Detection
    description: Detects RMM tools based on code signature subject name.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Child Process of RMM Tools
    description: Detects suspicious child processes spawned by known RMM tools
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Adversaries may install legitimate remote monitoring and management (RMM) tools or remote access software on compromised endpoints for command-and-control (C2), persistence, and execution of native commands. This can allow attackers to maintain persistent access, execute commands remotely, and potentially deploy further malicious payloads. This detection identifies the first-time execution of processes associated with commonly abused RMM tools on a given host within a configurable history window. By detecting these first-time occurrences, defenders can identify potentially unauthorized or malicious use of RMM tools before they are used for more damaging activities. This rule leverages process names and code signature information to identify known RMM tools. The rule has been seen detecting abused tools since April 2023.

## Attack Chain

1.  The attacker gains initial access to the target system (e.g., through phishing, exploitation of a vulnerability, or compromised credentials).
2.  The attacker installs a legitimate RMM tool or remote access software such as TeamViewer, AnyDesk, or ScreenConnect.
3.  The RMM tool is configured to allow remote access and control.
4.  The attacker uses the RMM tool to establish a persistent connection to the compromised system.
5.  The attacker executes commands remotely, potentially to gather information, move laterally, or install additional malware.
6.  The attacker may use the RMM tool to exfiltrate sensitive data from the compromised system.
7.  The attacker maintains persistence using the RMM tool, allowing continued access to the compromised system.
8.  The attacker deploys ransomware across the environment leveraging remote code execution capabilities.

## Impact

A successful attack involving the use of RMM tools can lead to significant damage, including data theft, system compromise, and financial loss. The use of RMM tools can also provide attackers with a persistent foothold in the network, allowing them to conduct long-term espionage or sabotage operations. Recent reports indicate that domain-wide ransomware has been deployed leveraging abused RMM tools. If successful, this attack can lead to complete data encryption and significant operational disruption.

## Recommendation

*   Deploy the Sigma rule "First Time Seen Remote Monitoring and Management Tool" to your SIEM to detect the initial execution of RMM tools on hosts, and tune the 7-day history window for your environment.
*   Investigate any alerts generated by the Sigma rule, focusing on the process execution chain (parent process tree) to identify potentially malicious activity.
*   Enforce that only tooling approved by IT policy should be used for remote access purposes, and only by authorized staff.
*   Enable process creation logging (e.g., Sysmon) with code signature monitoring on Windows endpoints to ensure the required data sources are available for detection.
*   Consider adding a rule exception for approved tools (e.g., Velociraptor) or excluding specific processes (e.g., `process.name: "Velociraptor.exe"`) to reduce false positives.
