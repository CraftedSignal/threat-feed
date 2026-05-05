---
title: Outlook Dialogs Disabled by Unusual Process
slug: 2024-01-outlook-dialog-disabled
description: The detection identifies the modification of the Windows Registry key 'PONT_STRING' under Outlook Options by a process other than Outlook.exe, potentially indicating malware activity such as NotDoor.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - outlook
  - registry_modification
  - malware
  - notdoor
vendors:
  - Microsoft
  - Splunk
products:
  - Outlook
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk Enterprise
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_outlook_dialogs_disabled_from_unusual_process.yml
  - https://lab52.io/blog/analyzing-notdoor-inside-apt28s-expanding-arsenal/
  - https://hackread.com/russian-apt28-notdoor-backdoor-microsoft-outlook/
rules:
  - title: Outlook Dialogs Disabled by Non-Outlook Process
    description: Detects modification of the PONT_STRING registry key in Outlook by a non-Outlook process.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1112
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Process Modifying Outlook Registry Key
    description: Detects any process other than Outlook modifying specific Outlook registry keys related to security or settings.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1112
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This threat brief addresses a technique where a process other than Outlook modifies the `PONT_STRING` registry value within Outlook's options. This modification disables certain dialog popups within Outlook, which can allow malicious scripts or actions to execute without user consent or notification. The activity is associated with malware families such as NotDoor. Attackers may leverage this to harvest email information or bypass security warnings. The technique involves modifying the Windows Registry key `HKEY_CURRENT_USER\Software\Microsoft\Office\<version>\Outlook\Options\General\PONT_STRING`.

## Attack Chain

1.  An attacker gains initial access to the system (e.g., through phishing or exploiting a software vulnerability).
2.  The attacker executes a malicious program or script (e.g., PowerShell or VBScript).
3.  The malicious program identifies the Outlook installation and its corresponding registry path.
4.  The malicious program modifies the `PONT_STRING` value under the `HKEY_CURRENT_USER\Software\Microsoft\Office\<version>\Outlook\Options\General\` key.
5.  This modification disables Outlook's dialog popups.
6.  The attacker executes further malicious actions, such as harvesting email credentials or injecting malicious content into emails, without user prompts.
7.  Exfiltrate data.

## Impact

Successful exploitation allows attackers to bypass security warnings and execute malicious code within the context of Microsoft Outlook. This can lead to unauthorized access to sensitive email data, credential theft, and the deployment of further malware. While the number of affected organizations is currently unknown, any organization using Microsoft Outlook is potentially at risk. Disabling Outlook dialogs is a common tactic used by malware families like NotDoor to facilitate data exfiltration.

## Recommendation

*   Enable Sysmon Event ID 13 (Registry events) to monitor registry modifications, as indicated in the rule's `data_source`.
*   Deploy the Sigma rule `Outlook Dialogs Disabled by Non-Outlook Process` to detect this specific registry modification. Tune the rule using the filter macro as described in the original source.
*   Investigate any registry modifications to the `HKEY_CURRENT_USER\Software\Microsoft\Office\<version>\Outlook\Options\General\PONT_STRING` key by processes other than `Outlook.exe`.
*   Implement application control policies to restrict the execution of unauthorized or unknown scripts and executables.
