---
title: Mounting Hidden or WebDav Remote Shares via Net.exe
slug: 2024-01-03-mount-remote-shares
description: Adversaries may use net.exe to mount WebDav or hidden remote shares, indicating lateral movement or preparation for data exfiltration within a Windows environment.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - windows
  - net.exe
  - webdav
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_mount_hidden_or_webdav_share_net.toml
rules:
  - title: Detect Mounting Hidden or WebDav Remote Shares via Net.exe
    description: Detects the use of net.exe to mount a WebDav or hidden remote share, potentially indicating lateral movement or preparation for data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Mounting Hidden or WebDav Remote Shares via Net1.exe
    description: Detects the use of net1.exe to mount a WebDav or hidden remote share, potentially indicating lateral movement or preparation for data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the use of `net.exe` and `net1.exe` by attackers to mount WebDav or hidden remote shares on Windows systems. This technique, often employed for lateral movement or data exfiltration preparation, involves leveraging the native Windows networking tool to establish connections to remote resources. Defenders should be aware that threat actors may exploit these legitimate tools to blend in with normal network activity. The detection strategy focuses on identifying specific command patterns associated with mounting hidden or WebDav shares, while excluding benign operations such as share deletion. This activity may lead to unauthorized access to sensitive data or further compromise of the network. The rule was last updated on 2026/04/07.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to a Windows system through various means (e.g., phishing, exploiting a vulnerability).
2.  **Account Discovery (T1087):** The attacker uses commands to discover available accounts and network resources to identify potential targets for lateral movement.
3.  **Remote Service (T1021.002):** The attacker attempts to mount a hidden or WebDav remote share using `net.exe` or `net1.exe`.
4.  **Share Discovery:** The attacker leverages `net.exe` with the `use` argument to enumerate available network shares. This is often combined with discovery of hidden shares using specific patterns.
5.  **Credentialed Access:** Attacker uses compromised credentials (T1078) to authenticate to the remote share if required.
6.  **Lateral Movement:** The attacker uses the mounted share to move laterally to other systems on the network.
7.  **Data Exfiltration Preparation:** The attacker stages data on the mounted share for subsequent exfiltration.
8.  **Data Exfiltration:** The attacker exfiltrates the staged data from the mounted share to an external location.

## Impact

A successful attack can lead to unauthorized access to sensitive data, lateral movement within the network, and data exfiltration. The compromise of even a single endpoint can provide a foothold for attackers to expand their reach and steal valuable information. While specific victim counts and sectors are not detailed in the source, the potential impact spans across any organization utilizing Windows-based networks and file-sharing protocols.

## Recommendation

*   Deploy the "Mounting Hidden or WebDav Remote Shares" rule to your SIEM to detect suspicious `net.exe` usage (rule).
*   Monitor process creation events for the execution of `net.exe` or `net1.exe` with arguments related to mounting network shares (log source).
*   Implement network segmentation to limit lateral movement and reduce the potential impact of compromised systems (general security practice).
*   Investigate and exclude legitimate uses of `net.exe` for mounting network drives by internal IP addresses or user accounts to reduce false positives (rule).
*   Enhance monitoring and alerting for suspicious network activity, including outbound connections that may indicate data exfiltration (general security practice).
*   Review and harden account access controls to prevent unauthorized access to network shares (general security practice).
