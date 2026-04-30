---
title: Powercat PowerShell Implementation Detection
slug: 2024-11-powercat-detection
description: Adversaries may leverage Powercat, a PowerShell implementation of Netcat, to establish command and control channels or perform lateral movement within a compromised network.
date: "2024-11-04T14:27:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - command-and-control
  - execution
  - lateral-movement
  - powershell
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1095
    technique_name: Non-Application Layer Protocol
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nmap.org/ncat/
  - https://github.com/besimorhino/powercat
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1095/T1095.md
rules:
  - title: Detect Powercat Use via PowerShell Classic Logs
    description: Detects the execution of Powercat via PowerShell Classic logs based on the presence of 'powercat ' or 'powercat.ps1' in the logs.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
      - T1095
    data_sources:
      - ps_classic_start
      - windows
  - title: Detect Powercat Script Download
    description: Detects the download of powercat.ps1 script from the internet using powershell
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
      - T1095
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Powercat is a PowerShell script that functions similarly to the traditional Netcat utility, allowing for network communication using TCP and UDP. Attackers can use Powercat to establish reverse shells, transfer files, and perform port scanning within a compromised environment. This activity is often employed during post-exploitation phases to maintain access and propagate further into the network. Defenders should be aware of PowerShell scripts invoking Powercat, especially in environments…
