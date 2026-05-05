---
title: Windows Registry Modification to Disable Registry Tools
slug: 2024-01-disable-registry-tool
description: This analytic detects modifications to the Windows registry, specifically targeting the 'DisableRegistryTools' key, which is a common tactic used by malware for persistence and defense evasion by preventing the removal of malicious entries.
date: "2024-01-03T18:15:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - persistence
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Windows
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://any.run/report/ea4ea08407d4ee72e009103a3b77e5a09412b722fdef67315ea63f22011152af/a866d7b1-c236-4f26-a391-5ae32213dfc4#registry
rules:
  - title: Detect Registry Modification to Disable Registry Tools
    description: Detects modification of the Windows registry to disable registry tools by setting the DisableRegistryTools value to 0x00000001.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1112
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Process Modifying DisableRegistryTools Value
    description: Detects processes that are modifying the DisableRegistryTools registry value.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This detection focuses on identifying attempts to disable the Windows Registry Editor (regedit) through modifications to the `DisableRegistryTools` value in the Windows registry. Attackers, particularly malware such as Remote Access Trojans (RATs) and trojans, often employ this technique to prevent defenders from removing malicious registry entries. By setting the `DisableRegistryTools` value to `0x00000001`, the Registry Editor is effectively disabled, hindering incident response and allowing malware to maintain persistence on the compromised system. This activity is a strong indicator of malicious intent and requires immediate investigation. The analytic leverages data from Endpoint.Registry data model from Splunk.

## Attack Chain

1.  The attacker gains initial access to the system through an exploit, social engineering, or other means.
2.  The attacker executes a malicious binary or script on the compromised system.
3.  The malicious script attempts to modify the Windows registry.
4.  The script targets the registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.
5.  The script sets the `DisableRegistryTools` value to `0x00000001`.
6.  The Registry Editor is disabled, preventing the user from modifying registry entries.
7.  The malware establishes persistence and continues malicious activities.

## Impact

A successful attack that disables registry tools can significantly impede incident response efforts. By preventing administrators and security tools from accessing and modifying the registry, attackers can maintain persistence, evade detection, and hinder remediation efforts. This can lead to prolonged infections, data breaches, and further compromise of the affected system.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious modifications to the `DisableRegistryTools` registry key.
*   Enable Sysmon Event ID 13 (Registry events) with the official Sysmon TA to capture the necessary registry modification events.
*   Investigate any alerts triggered by the Sigma rule, focusing on the process associated with the registry modification.
*   Review and harden registry permissions to prevent unauthorized modifications.
