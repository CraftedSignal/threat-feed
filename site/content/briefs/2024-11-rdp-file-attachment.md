---
title: Remote Desktop File Opened from Suspicious Path
slug: 2024-11-rdp-file-attachment
description: Adversaries may abuse RDP files delivered via phishing from suspicious locations to gain unauthorized access to systems.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - initial-access
  - rdp
  - phishing
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - M365 Defender
  - Sysmon
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - CrowdStrike Falcon
affected_os:
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
    description: Detects when mstsc.exe opens an RDP file from a suspicious directory, indicating potential phishing or malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious MSTSC Execution with RDP File Argument
    description: Detects mstsc.exe being executed with an RDP file as an argument, which could indicate malicious use of RDP.
    platform: sigma
    severity: low
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly using malicious Remote Desktop Protocol (RDP) files to gain initial access to systems. These RDP files, often delivered via spearphishing attachments, contain connection settings that, when opened, can compromise a system. This technique allows adversaries to bypass traditional security measures by leveraging a legitimate tool (mstsc.exe) with a malicious configuration file. The observed activity involves opening RDP files from suspicious locations like Downloads, temporary folders (AppData\\Local\\Temp), and Outlook content cache (INetCache\\Content.Outlook). This campaign has been observed as recently as October 2024, where Midnight Blizzard conducted large-scale spear-phishing using RDP files. Defenders should monitor for the execution of mstsc.exe with RDP files from untrusted locations.

## Attack Chain

1.  The attacker crafts a spearphishing email containing a malicious RDP file as an attachment.
2.  The victim receives the email and, lured by social engineering, downloads the attached RDP file to a local directory, often the Downloads folder.
3.  The victim double-clicks the RDP file, initiating the execution of `mstsc.exe`.
4.  `mstsc.exe` reads the connection settings from the RDP file, which may include malicious configurations such as altered gateway settings or credential theft mechanisms.
5.  `mstsc.exe` attempts to establish a remote desktop connection based on the RDP file's settings.
6.  If the connection is successful, the attacker gains unauthorized access to the remote system.
7.  The attacker may then perform reconnaissance, move laterally, and escalate privileges within the compromised network.
8.  The final objective could be data exfiltration, ransomware deployment, or establishing persistent access.

## Impact

A successful attack using malicious RDP files can lead to unauthorized access to sensitive systems and data. The consequences range from data breaches and financial loss to complete system compromise and disruption of operations. The Microsoft Security blog reported a large-scale spear-phishing campaign utilizing RDP files as recently as October 2024. The targets may be across various sectors, with potentially widespread impact depending on the attacker's objectives and the scope of the compromised network.

## Recommendation

*   Deploy the Sigma rule `Remote Desktop File Opened from Suspicious Path` to your SIEM and tune for your environment, focusing on the specified file paths and `mstsc.exe` execution.
*   Enable process creation logging with command-line arguments to capture the execution of `mstsc.exe` and the paths of the RDP files being opened.
*   Educate users on the risks associated with opening RDP files from untrusted sources, particularly those received as email attachments.
*   Implement strict email filtering to block or quarantine emails with RDP attachments from external sources.
*   Monitor network connections for unusual RDP traffic originating from systems where suspicious RDP files were executed.
