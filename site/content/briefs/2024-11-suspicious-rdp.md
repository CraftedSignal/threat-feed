---
title: Suspicious RDP File Execution
slug: 2024-11-suspicious-rdp
description: This rule identifies attempts to open a remote desktop file from suspicious paths, indicative of adversaries abusing RDP files for initial access via phishing.
date: "2026-04-20T21:38:09Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - rdp
  - phishing
  - initial-access
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/
  - https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/
  - https://shorsec.io/blog/malrdp-implementing-rouge-rdp-manually/
rules:
  - title: Remote Desktop File Opened from Suspicious Path
    description: Detects the execution of mstsc.exe with an RDP file from suspicious paths, indicating potential malicious RDP usage.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: RDP Connection Attempt from Outlook Temp Directory
    description: Detects RDP connections initiated from the Outlook temporary content directory, which can indicate a phishing attempt via malicious RDP attachments.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies the execution of `mstsc.exe` (Remote Desktop Connection) with an RDP file located in suspicious directories on Windows systems. Adversaries may use malicious RDP files delivered via phishing campaigns as an initial access vector. These files, containing connection settings, can be placed in locations such as the Downloads folder, temporary directories, or Outlook's content cache. The rule focuses on detecting RDP files opened from unusual paths, which can signal unauthorized access or malicious activity. The behavior was observed in conjunction with the Midnight Blizzard campaign in October 2024. This detection helps defenders identify potential RDP-based attacks and investigate suspicious user behavior.

## Attack Chain

1.  The attacker crafts a spearphishing email with a malicious RDP file attachment (T1566.001).
2.  The victim receives the email and downloads the RDP file to a common location such as the Downloads folder.
3.  The user executes the downloaded RDP file, initiating the `mstsc.exe` process (T1204.002).
4.  The `mstsc.exe` process attempts to establish a remote connection to a malicious server controlled by the attacker.
5.  The attacker may exploit vulnerabilities in the RDP service or use credential harvesting techniques to gain access to the remote system.
6.  Upon successful connection, the attacker performs reconnaissance activities, such as network scanning and user enumeration.
7.  The attacker moves laterally within the network, exploiting additional vulnerabilities or using stolen credentials.
8.  The attacker achieves their objective, such as data exfiltration or deploying ransomware.

## Impact

Successful exploitation via malicious RDP files can lead to unauthorized access to internal systems, data breaches, and potential ransomware deployment. While the number of victims and targeted sectors is unspecified, the impact can be significant, especially if the compromised systems have access to sensitive data or critical infrastructure. This can result in financial losses, reputational damage, and operational disruptions.

## Recommendation

*   Enable Sysmon process creation logging to detect the execution of `mstsc.exe` and capture the command-line arguments used to launch the process.
*   Deploy the Sigma rule "Remote Desktop File Opened from Suspicious Path" to your SIEM to detect RDP files opened from suspicious locations.
*   Educate users about the risks of opening RDP files from untrusted sources, especially those received via email.
*   Implement application control policies to restrict the execution of `mstsc.exe` from untrusted directories.
*   Monitor network connections originating from systems where `mstsc.exe` has been executed to identify suspicious remote connections.
