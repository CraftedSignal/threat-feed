---
title: Detection of NetExec Hacktool Execution
slug: 2024-01-netexec-execution
description: The threat brief details the detection of NetExec (formerly CrackMapExec), a post-exploitation tool used for Active Directory penetration testing and network enumeration, often employed by threat actors for lateral movement and credential harvesting.
date: "2024-01-03T14:35:00Z"
severities:
  - high
actors:
  - Red Teams
tags:
  - pentest
  - post-exploitation
  - lateral-movement
  - active-directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://thedfirreport.com/2025/12/17/cats-got-your-files-lynx-ransomware/
  - https://github.com/Pennyw0rth/NetExec
  - https://www.netexec.wiki/
rules:
  - title: HackTool - NetExec Execution
    description: Detects execution of the hacktool NetExec based on process name and command-line arguments.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - lateral-movement
    techniques:
      - T1018
      - T1021
    data_sources:
      - process_creation
      - windows
  - title: NetExec Execution with Specific Protocol
    description: Detects NetExec execution focusing on specific protocols used for lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral-movement
    techniques:
      - T1021
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

NetExec, previously known as CrackMapExec, is a post-exploitation tool commonly used during Active Directory penetration testing. It is also favored by red teams and malicious actors for reconnaissance, lateral movement, and credential harvesting within Windows networks. This tool allows for the enumeration of hosts, exploitation of network services, and remote command execution. The use of NetExec in an enterprise environment is considered suspicious due to its capabilities for identifying…
