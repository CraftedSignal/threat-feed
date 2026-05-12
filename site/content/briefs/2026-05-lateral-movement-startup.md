---
title: Lateral Movement via Remote Startup Folder Modification
slug: 2026-05-lateral-movement-startup
description: Adversaries may achieve lateral movement by creating malicious files in remote Windows startup folders via RDP or SMB, leading to code execution upon system reboot or user logon.
date: "2026-05-12T17:47:19Z"
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
  - SentinelOne
  - Elastic
products:
  - m365_defender
  - sentinel_one_cloud_funnel
  - Elastic Endgame
  - Elastic Defend
  - Sysmon
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0007
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0007
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
references:
  - https://www.mdsec.co.uk/2017/06/rdpinception/
  - https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language
rules:
  - title: Lateral Movement via Startup Folder Modification
    description: Detects suspicious file creations in the startup folder of a remote system via RDP or SMB.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
      - persistence
    techniques:
      - T1021.001
      - T1021.002
    data_sources:
      - file_event
      - windows
  - title: Lateral Movement via Startup Folder Modification (PID 4)
    description: Detects suspicious file creations in the startup folder of a remote system via SMB, where the process ID is 4.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
      - persistence
    techniques:
      - T1021.002
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This detection identifies suspicious file creations within the startup directories of remote Windows systems. Attackers can leverage this technique for lateral movement by dropping malicious scripts or executables into these folders. These payloads are then executed automatically when the system restarts or a user logs in. The activity involves writing files to the startup folders via Remote Desktop Protocol (RDP) using TSClient mounted shares or Server Message Block (SMB) protocol. The targeted processes are typically `mstsc.exe` (Remote Desktop Connection) or processes with PID 4 (NT Kernel & System, often involved in SMB file operations). This technique allows attackers to gain persistence and execute code on remote systems, potentially leading to further compromise within the network.

## Attack Chain

1.  The attacker gains initial access to a system within the target network.
2.  The attacker uses RDP (via `mstsc.exe`) or SMB to connect to a remote target system.
3.  The attacker authenticates to the remote system using compromised credentials or other exploits.
4.  The attacker uses the RDP TSClient mounted share or SMB to access the remote system's file system.
5.  The attacker creates a malicious file (e.g., a script or executable) in the remote system's startup folder: `C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*` or `C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*`.
6.  The attacker may rename or modify the file to ensure it is executed upon system startup or user logon.
7.  The remote system is rebooted or a user logs on.
8.  The malicious file executes, granting the attacker code execution on the remote system, facilitating further lateral movement or other malicious activities.

## Impact

Successful exploitation allows attackers to execute arbitrary code on remote systems within the network. This can lead to further lateral movement, data exfiltration, installation of ransomware, or other malicious activities. The impact is significant because startup folders are a reliable persistence mechanism, ensuring that the malicious code is executed automatically. This technique is commonly used in targeted attacks and can be difficult to detect without proper monitoring.

## Recommendation

*   Enable Sysmon file creation logging (Event ID 11) to provide detailed information about file creation events for detection and investigation.
*   Deploy the Sigma rule "Lateral Movement via Startup Folder Modification" to your SIEM to detect suspicious file creations in startup folders via RDP or SMB based on process names and file paths.
*   Monitor network connections for SMB (port 445) and RDP (port 3389) activity to identify potential lateral movement attempts.
*   Implement access controls to restrict SMB and RDP access to only authorized users and systems to prevent unauthorized lateral movement.
*   Review and harden Group Policy settings to prevent modifications to startup folders by unauthorized users or processes.
