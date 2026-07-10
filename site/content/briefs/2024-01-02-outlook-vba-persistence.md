---
title: Microsoft Outlook VBA Template Persistence
slug: 2024-01-02-outlook-vba-persistence
description: Attackers establish persistence by installing a malicious VBA template in Microsoft Outlook, triggering scripts upon application startup by modifying the VBAProject.OTM file.
date: "2024-01-02T12:00:00Z"
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
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
references:
  - https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/
  - https://www.linkedin.com/pulse/outlook-backdoor-using-vba-samir-b-/
rules:
  - title: Outlook VBA Project Modification
    description: Detects modification of the Outlook VBA project file, indicating potential VBA macro-based persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137.001
    data_sources:
      - file_event
      - windows
  - title: Suspicious Process Modifying Outlook VBA Project
    description: Detects processes not typically associated with Outlook modifying the VBA project file.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1137.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Attackers are known to exploit Microsoft Outlook's VBA scripting capabilities to establish persistence on compromised systems. This involves installing rogue VBA templates, which contain malicious scripts, within the Outlook environment. These scripts are designed to automatically execute when Outlook starts, providing a persistent foothold for the attacker. The technique focuses on modifying the `VbaProject.OTM` file, which stores VBA project data for Outlook. This activity allows the attacker to maintain long-term access and potentially execute further malicious actions. The technique can be detected by monitoring file modifications to the `VbaProject.OTM` file.

## Attack Chain

1.  The attacker gains initial access to the target system (e.g., via compromised credentials or other means).
2.  The attacker crafts a malicious VBA script designed to perform actions such as downloading and executing additional payloads.
3.  The attacker modifies the `VbaProject.OTM` file, either by directly overwriting it or injecting malicious code.
4.  The modified `VbaProject.OTM` file is saved in the user's Outlook profile directory (e.g., `C:\Users\<user>\AppData\Roaming\Microsoft\Outlook\`).
5.  The attacker ensures that Outlook is restarted or instructs the victim to restart Outlook.
6.  Upon Outlook startup, the VBA script within `VbaProject.OTM` is automatically executed.
7.  The malicious VBA script connects to an external command-and-control (C2) server to download a secondary payload.
8.  The secondary payload is executed, allowing the attacker to perform actions such as data exfiltration or lateral movement.

## Impact

Successful exploitation allows attackers to maintain persistent access to the compromised system. The injected VBA code can perform a variety of malicious actions, including data exfiltration, credential theft, and lateral movement within the network. The technique can lead to significant data breaches and financial losses. Although the exact number of victims is not specified, this persistence technique is applicable across organizations that heavily rely on Microsoft Outlook.

## Recommendation

*   Monitor file modifications to `VbaProject.OTM` in user profile directories. Deploy the Sigma rule `Outlook VBA Project Modification` to detect suspicious changes.
*   Implement application control or whitelisting to restrict unauthorized modifications to Outlook VBA files.
*   Enable Sysmon file creation and modification logging to activate the rules above.
*   Regularly review and audit Outlook VBA settings to identify and remove any unauthorized or malicious scripts.
