---
title: SMB Registry Hive Exfiltration
slug: 2024-01-smb-registry-exfiltration
description: Detection of medium-sized registry hive files being created or modified on Server Message Block (SMB) shares, potentially indicating exfiltration of Security Account Manager (SAM) data for credential extraction.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - lateral-movement
  - exfiltration
  - windows
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
references:
  - https://www.elastic.co/security-labs/detect-credential-access
  - https://attack.mitre.org/techniques/T1003/
  - https://attack.mitre.org/techniques/T1003/002/
  - https://attack.mitre.org/tactics/TA0006/
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1021/002/
  - https://attack.mitre.org/tactics/TA0008/
  - https://attack.mitre.org/techniques/T1048/
  - https://attack.mitre.org/tactics/TA0010/
rules:
  - title: Registry Hive File Creation in SMB Share
    description: Detects the creation of a registry hive file on an SMB share by the SYSTEM process, potentially indicating credential exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - exfiltration
      - lateral_movement
    techniques:
      - T1003.002
      - T1021.002
      - T1048
    data_sources:
      - file_event
      - windows
  - title: Registry Hive File Modification in SMB Share
    description: Detects the modification of a registry hive file on an SMB share by the SYSTEM process, potentially indicating credential exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - exfiltration
      - lateral_movement
    techniques:
      - T1003.002
      - T1021.002
      - T1048
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This threat brief addresses the potential exfiltration of Windows registry hives via SMB shares, a tactic often employed after credential dumping. Attackers target sensitive hives like the Security Account Manager (SAM) to extract cached credentials. By copying these hives to an attacker-controlled system, they evade local host-based detection and facilitate offline credential decryption. The Elastic detection rule `a4c7473a-5cb4-4bc1-9d06-e4a75adbc494` identifies the creation or modification of registry hive files (identified by the "regf" header) exceeding 30KB on SMB shares, specifically when performed by the SYSTEM process (PID 4) under a user context associated with system accounts (S-1-5-21 or S-1-12-1). This behavior raises suspicion, particularly when observed outside expected file paths. Defenders should monitor for this activity as it often precedes lateral movement and further compromise.

## Attack Chain

1.  Attacker gains initial access to a Windows system.
2.  The attacker elevates privileges to SYSTEM or a similar high-privilege account.
3.  The attacker executes a credential dumping tool (e.g., `reg save HKLM\SAM sam.hive`) to extract the SAM registry hive.
4.  The attacker executes `reg save HKLM\SYSTEM system.hive` to extract the SYSTEM registry hive, enabling decryption of SAM secrets.
5.  The attacker connects to a remote SMB share (e.g., `\\attacker.example.com\share`) from the compromised host.
6.  The SYSTEM process (PID 4) creates or modifies a file on the SMB share, identified as a registry hive by its header ("regf").
7.  The exfiltrated registry hive file is larger than 30KB, bypassing size-based filtering.
8.  The attacker utilizes the exfiltrated SAM and SYSTEM hives to extract user credentials offline, facilitating lateral movement or further malicious activities.

## Impact

Successful exfiltration of registry hives can lead to widespread credential compromise, enabling attackers to move laterally within the network, access sensitive data, and potentially achieve domain dominance. The impact includes unauthorized access to critical systems, data breaches, and significant disruption of business operations. The number of affected systems directly correlates with the scope of credential access achieved by the attacker.

## Recommendation

*   Deploy the Elastic detection rule `a4c7473a-5cb4-4bc1-9d06-e4a75adbc494` or the Sigma rules provided in this brief to your SIEM and tune for your environment to detect registry hive exfiltration attempts.
*   Enable file creation and modification logging on SMB shares, specifically focusing on events associated with the SYSTEM process and registry hive file signatures, to increase visibility.
*   Review and harden SMB share permissions to restrict unauthorized access and prevent credential dumping from remote systems.
*   Investigate any alerts generated by these rules promptly, focusing on identifying the source host, the user account involved, and the destination SMB share.
*   Implement multi-factor authentication (MFA) for all user accounts to mitigate the impact of credential theft.
