---
title: Potential Ransomware Behavior - Note Files Dropped via SMB
slug: 2024-01-22-potential-ransomware-smb
description: This rule detects potential ransomware behavior by identifying the creation of multiple files with the same name over SMB by the SYSTEM account, potentially indicating remote execution of ransomware dropping note files.
date: "2024-01-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ransomware
  - impact
  - lateral-movement
  - windows
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/impact_high_freq_file_renames_by_kernel.toml
  - https://news.sophos.com/en-us/2023/12/21/akira-again-the-ransomware-that-keeps-on-taking/
rules:
  - title: Potential Ransomware Note File Dropped via SMB
    description: Detects the creation of multiple files with the same name over SMB by the SYSTEM account, indicating potential ransomware activity.
    platform: sigma
    severity: medium
    tactics:
      - impact
      - lateral_movement
    techniques:
      - T1021.002
      - T1486
    data_sources:
      - file_event
      - windows
  - title: High Frequency File Creation by SYSTEM over SMB
    description: Detects rapid file creation events by the SYSTEM account over SMB within a short time frame.
    platform: sigma
    severity: high
    tactics:
      - impact
      - lateral_movement
    techniques:
      - T1021.002
      - T1486
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This detection identifies potential ransomware activity through the rapid creation of ransom notes via SMB shares. The rule focuses on file creation events originating from the SYSTEM account (PID 4), targeting common ransom note file extensions like .txt, .html, .pdf, and image files. This activity suggests an attacker has achieved lateral movement and is deploying ransom notes across multiple systems. The rule aggregates events within a 60-second window to reduce false positives and focus on high-frequency creation patterns indicative of automated ransomware deployment. Successful detection can help defenders quickly identify and contain ransomware outbreaks before widespread encryption occurs. The original Elastic detection rule was published on 2024-05-03 and updated on 2026-05-04.

## Attack Chain

1.  The attacker gains initial access to a system through an exploit or compromised credentials.
2.  The attacker moves laterally to other systems on the network using valid accounts or exploits. (T1021.002 - SMB/Windows Admin Shares)
3.  The attacker uses a tool to remotely create files over SMB. (T1021.002 - SMB/Windows Admin Shares)
4.  The SYSTEM account (PID 4) on a compromised host is used to create multiple files with the same name but different paths (C:\*) over SMB.
5.  The created files have file extensions commonly associated with ransom notes: .txt, .htm, .html, .hta, .pdf, .jpg, .bmp, .png.
6.  The files are dropped into at least 3 unique paths within a short time frame (60 seconds).
7.  The attacker encrypts data and leaves the ransom notes to instruct victims on how to pay the ransom. (T1486 - Data Encrypted for Impact)
8.  The organization experiences data loss, financial damage, and reputational harm.

## Impact

Successful ransomware attacks can lead to significant data loss, financial costs associated with ransom payments, recovery efforts, and reputational damage. Organizations may experience business disruption, regulatory fines, and legal liabilities. The Akira ransomware group, referenced in the original rule's documentation, has been known to target various sectors, demanding substantial ransoms from victims. The widespread distribution of ransom notes indicates an advanced stage of the ransomware attack, necessitating immediate containment to prevent further data encryption and system compromise.

## Recommendation

*   Deploy the Sigma rule `Potential Ransomware Note File Dropped via SMB` to your SIEM to detect suspicious file creation activity indicative of ransomware deployment.
*   Enable Elastic Defend for enhanced endpoint detection and response capabilities, as recommended in the rule's setup instructions.
*   Monitor incoming network connections to port 445 (SMB) on critical assets, as suggested in the rule's triage analysis.
*   Investigate file names with unusual extensions to identify potential ransom notes, as mentioned in the triage analysis.
*   Isolate any hosts identified as creating multiple note files over SMB to prevent further lateral movement and data encryption, as described in the rule's response and remediation steps.
*   Review and enforce network segmentation policies to limit lateral movement and reduce the impact of potential ransomware attacks (TA0008).
