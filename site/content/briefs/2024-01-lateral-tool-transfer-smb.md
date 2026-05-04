---
title: Potential Lateral Tool Transfer via SMB Share
slug: 2024-01-lateral-tool-transfer-smb
description: The rule identifies the creation or change of a Windows executable file over network shares, indicating potential lateral tool transfer via SMB, which adversaries may use to move tools between systems in a compromised environment.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - lateral-movement
  - smb
  - file-transfer
  - windows
vendors:
  - Elastic
  - Cisco
products:
  - Elastic Defend
  - CISCO Talos
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
references:
  - https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper
  - https://www.elastic.co/security-labs/hunting-for-lateral-movement-using-event-query-language
rules:
  - title: Detect Executable File Creation on SMB Share
    description: Detects the creation of executable files on SMB shares, which could indicate lateral tool transfer.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
      - T1570
    data_sources:
      - file_event
      - windows
  - title: Detect Network Connection to SMB Followed by File Creation
    description: Detects a network connection to SMB (port 445) followed by the creation of an executable file, suggesting lateral tool transfer.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
      - T1570
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This detection rule identifies the potential transfer of malicious tools within a Windows environment using SMB shares. Attackers commonly leverage SMB shares to propagate malware, tools, or scripts to compromised systems for lateral movement. The rule focuses on detecting the creation or modification of executable files (e.g., .exe, .dll, .ps1) on network shares, which is a strong indicator of malicious activity. The rule leverages Elastic Defend data to detect this activity and can be used to identify systems that may be compromised. This technique is used to deploy additional payloads, credential dumpers, or other malicious tools.

## Attack Chain

1. An attacker gains initial access to a system within the network.
2. The attacker identifies accessible SMB shares within the compromised environment.
3. The attacker uses the compromised system to connect to a target SMB share (port 445) on another system.
4. The attacker copies an executable file (e.g., malware, a credential dumping tool, or a PowerShell script) to the SMB share.
5. The target system detects a new file creation or change event on the SMB share.
6. A user or process on the target system executes the transferred file.
7. The executed file performs malicious actions on the target system, such as credential theft or lateral movement.
8. The attacker uses the newly compromised system to further expand their access within the network.

## Impact

Successful exploitation allows attackers to propagate malware or malicious tools throughout the network, leading to widespread compromise. Lateral movement enables attackers to access sensitive data, escalate privileges, and ultimately achieve their objectives, which may include data exfiltration, ransomware deployment, or system disruption. The rule aims to detect this activity early in the attack chain and mitigate potential damage.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect suspicious executable file creation/modification events on SMB shares.
*   Enable Elastic Defend on all Windows endpoints to provide the necessary data for the detection rule to function.
*   Investigate any alerts triggered by the Sigma rules, focusing on the process execution chain, file reputation, and user activity.
*   Review and restrict write access to network shares to minimize the risk of unauthorized file transfers.
*   Monitor network connections to port 445 (SMB) for suspicious activity, especially connections originating from unusual source IPs (Sigma rule, log source).
