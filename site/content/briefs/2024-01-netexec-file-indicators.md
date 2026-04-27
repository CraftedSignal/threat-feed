---
title: NetExec File Creation Detection
slug: 2024-01-netexec-file-indicators
description: This brief covers the detection of NetExec, a post-exploitation and lateral movement tool, through monitoring for unique file creation patterns associated with its execution and file extraction in Windows environments.
date: "2024-01-18T12:00:00Z"
severities:
  - high
tags:
  - netexec
  - crackmapexec
  - lateral-movement
  - post-exploitation
  - hacktool
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1021.002
    technique_name: 'Remote Services: SMB/Windows Admin Shares'
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/Pennyw0rth/NetExec
  - https://www.netexec.wiki/
rules:
  - title: Detect NetExec File Creation
    description: Detects the creation of NetExec data files within the temporary directory.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
      - lateral-movement
    techniques:
      - T1021.002
      - T1059.005
    data_sources:
      - file_event
      - windows
  - title: Detect NetExec Image Path
    description: Detects NetExec execution based on its image path.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
      - lateral-movement
    techniques:
      - T1021.002
      - T1059.005
    data_sources:
      - file_event
      - windows
rules_count: 2
---

NetExec (formerly CrackMapExec) is a widely used post-exploitation tool favored by penetration testers and malicious actors for Active Directory enumeration, credential harvesting, and remote code execution. When executed on a Windows system, NetExec extracts its embedded data files into a temporary directory named "_MEI" followed by a random string, located under the user's Temp folder. A specific subdirectory, "\nxc\data\", within this extraction path contains files unique to NetExec. These…
