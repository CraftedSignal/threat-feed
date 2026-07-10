---
title: Lateral Movement via Startup Folder File Creation
slug: 2024-01-lateral-movement-startup
description: Adversaries may move laterally by dropping malicious scripts or executables into a remote system's startup folder via RDP or SMB, enabling execution upon reboot or user logon.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - persistence
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://www.mdsec.co.uk/2017/06/rdpinception/
  - https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language
rules:
  - title: Lateral Movement via Startup Folder Creation by RDP
    description: Detects file creation in the startup folder of a remote system via RDP (mstsc.exe)
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
      - persistence
    techniques:
      - T1021.001
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Lateral Movement via Startup Folder Creation by System Account
    description: Detects file creation in the startup folder of a remote system via SMB (PID 4)
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
      - persistence
    techniques:
      - T1021.002
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This detection strategy focuses on identifying suspicious file creation events within Windows startup folders on remote systems. Attackers may leverage remote access protocols like RDP or SMB to place malicious scripts or executables in these directories. This technique allows the adversary to achieve persistence and lateral movement by ensuring the malicious file is executed automatically when the system restarts or a user logs in. The primary indicator is file creation or modification within specific startup folder paths, particularly when associated with processes like `mstsc.exe` (Remote Desktop Client) or processes with a PID of 4 (typically associated with the System process interacting with network shares). This activity helps attackers establish a foothold for further malicious actions within the network.

## Attack Chain

1.  The attacker gains initial access to a user account, possibly through credential theft or phishing.
2.  The attacker uses RDP (mstsc.exe) or SMB to connect to a target Windows system.
3.  The attacker navigates to the remote system's startup folder via a mounted share or administrative share. The typical paths are `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` or `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\`.
4.  The attacker creates or copies a malicious file (e.g., a script, executable, or shortcut) into the startup folder.
5.  The system is rebooted or the user logs on.
6.  The operating system executes the malicious file from the startup folder.
7.  The malicious file performs unauthorized actions such as installing malware, establishing persistence, or gathering credentials.
8.  The attacker leverages the compromised system to move laterally to other systems on the network.

## Impact

Successful exploitation can lead to widespread compromise within an organization's network. Attackers can establish persistent access, steal sensitive data, deploy ransomware, or disrupt critical services. The number of affected systems can range from a few workstations to entire domains, depending on the attacker's objectives and the organization's security posture.

## Recommendation

*   Deploy the "Lateral Movement via Startup Folder" Sigma rule to your SIEM to detect suspicious file creation events in startup folders associated with remote access activity.
*   Monitor process creation events for processes originating from the Windows Startup folders for unexpected or unsigned binaries.
*   Enable Sysmon file creation logging (EventCode 11) and network connection logging (EventCode 3) to provide visibility into file modifications and network activity related to RDP and SMB connections to activate the Sigma rules.
*   Enforce the principle of least privilege to limit the impact of compromised accounts and restrict access to sensitive resources (T1021).
*   Implement network segmentation to limit lateral movement capabilities within the network (TA0008).
