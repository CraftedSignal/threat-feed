---
title: Persistence via Malicious Microsoft Outlook VBA Template
slug: 2024-01-outlook-vba-persistence
description: Attackers establish persistence by installing a malicious VBA template in Microsoft Outlook, triggering scripts upon application startup by modifying the VBAProject.OTM file, detected by monitoring for unauthorized file modifications.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - vba
  - outlook
  - windows
vendors:
  - Microsoft
products:
  - Outlook
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
references:
  - https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/
  - https://www.linkedin.com/pulse/outlook-backdoor-using-vba-samir-b-/
rules:
  - title: Detect Outlook VBA Template Modification
    description: Detects the creation or modification of the VbaProject.OTM file, indicating a potential persistence attempt via malicious Outlook VBA.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137.001
    data_sources:
      - file_event
      - windows
  - title: Detect Outlook VBA Project from Suspicious Process
    description: Detects process creating VBA Project files that are not Outlook
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can leverage Microsoft Outlook's VBA scripting capabilities to establish persistence on compromised systems. This is achieved by installing malicious VBA templates within the Outlook environment. These templates are designed to execute upon application startup, granting the attacker sustained access and control. The attack centers around unauthorized modifications to the `VbaProject.OTM` file, a critical component for VBA script storage in Outlook. This technique allows threat actors to maintain a foothold even after system restarts or user logoffs. Defenders need to monitor for suspicious changes to this file to identify and mitigate potential compromises.

## Attack Chain

1.  The attacker gains initial access to the target system, potentially through phishing or other social engineering methods (not detailed in source).
2.  The attacker identifies a user with Microsoft Outlook installed and running on a Windows system.
3.  The attacker modifies or replaces the existing `VbaProject.OTM` file located in the user's Outlook profile (`C:\Users\*\AppData\Roaming\Microsoft\Outlook\`).
4.  The modified `VbaProject.OTM` file contains malicious VBA code designed to execute when Outlook starts.
5.  The victim launches Microsoft Outlook.
6.  The malicious VBA code within `VbaProject.OTM` executes automatically upon Outlook startup, establishing persistence.
7.  The VBA script can perform various malicious actions, such as downloading and executing additional payloads, establishing command and control, or exfiltrating data.

## Impact

Successful exploitation can lead to persistent access to the compromised system, allowing attackers to steal sensitive information, deploy ransomware, or use the system as a staging ground for further attacks within the network. The number of victims and specific sectors targeted depends on the attacker's objectives and scope of the campaign. If the attack succeeds, an attacker could gain complete control over the user's email account and associated data, leading to significant data breaches and financial losses.

## Recommendation

*   Deploy the Sigma rule `Detect Outlook VBA Template Modification` to your SIEM to identify unauthorized modifications to the `VbaProject.OTM` file based on file creation events.
*   Enable Sysmon file creation logging (Event ID 11) to activate the `Detect Outlook VBA Template Modification` rule.
*   Implement application control policies to restrict unauthorized modifications to Outlook VBA files as described in the "Response and remediation" section of the source.
*   Monitor file creation events related to `VbaProject.OTM` in the specified paths (`C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM`) as highlighted in the rule query.
