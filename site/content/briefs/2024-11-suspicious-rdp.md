---
title: Suspicious RDP File Execution
slug: 2024-11-suspicious-rdp
description: This rule identifies attempts to open a remote desktop file from suspicious paths, indicative of adversaries abusing RDP files for initial access via phishing.
date: "2026-04-20T21:38:09Z"
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

This detection identifies the execution of `mstsc.exe` (Remote Desktop Connection) with an RDP file located in suspicious directories on Windows systems. Adversaries may use malicious RDP files delivered via phishing campaigns as an initial access vector. These files, containing connection settings, can be placed in locations such as the Downloads folder, temporary directories, or Outlook's content cache. The rule focuses on detecting RDP files opened from unusual paths, which can signal…
