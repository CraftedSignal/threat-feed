---
title: Windows SmartScreen Disabled via Registry Modification
slug: 2024-01-disable-smartscreen
description: Attackers disable Windows SmartScreen protection by modifying specific registry keys to evade detection and facilitate malware deployment.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - smartscreen
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Impair Defenses
references:
  - https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/disable_windows_smartscreen_protection.yml
rules:
  - title: SmartScreen Disabled via Registry
    description: Detects modification of Windows Registry keys to disable SmartScreen protection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: SmartScreen Disabled via Registry (Process)
    description: Detects a process modifying Windows Registry keys to disable SmartScreen protection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to disable Windows SmartScreen to evade detection and deliver malware payloads. Windows SmartScreen provides a warning system against phishing and malware, so disabling it can significantly increase the risk of successful attacks. This is often done by Remote Access Trojans (RATs) to evade detection while downloading additional payloads. The technique involves modifying specific registry keys to turn off the SmartScreen feature. This allows attackers to bypass security measures designed to protect users from malicious software and phishing attempts.

## Attack Chain

1.  Initial Access: The attacker gains initial access to the system through unspecified means, such as exploiting a vulnerability or using stolen credentials.
2.  Privilege Escalation: The attacker escalates privileges if necessary to gain the required permissions to modify the registry.
3.  Registry Modification: The attacker modifies the registry keys associated with SmartScreen to disable the protection. This includes setting the `SmartScreenEnabled` value under `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\` or `EnableSmartScreen` under `HKLM\Microsoft\Windows\System\` to "Off" or "0".
4.  Persistence: The attacker may establish persistence to ensure that the SmartScreen remains disabled even after a reboot.
5.  Payload Delivery: With SmartScreen disabled, the attacker downloads and executes malicious payloads, such as malware or RATs, without triggering security warnings.
6.  Lateral Movement: The attacker may use the compromised system to move laterally within the network, targeting other systems and resources.
7.  Data Exfiltration: The attacker exfiltrates sensitive data from the compromised system or network.

## Impact

Disabling SmartScreen can lead to a significant increase in successful malware infections and phishing attacks. Users are no longer warned about potentially malicious files or websites, making them more vulnerable to exploitation. This can result in data breaches, financial losses, and reputational damage. While specific numbers are unavailable, the impact is potentially widespread across organizations that rely on Windows SmartScreen as a security measure.

## Recommendation

*   Monitor registry modifications for changes to the `SmartScreenEnabled` and `EnableSmartScreen` registry keys and values using the provided Sigma rule (`SmartScreenDisabledViaRegistry`).
*   Enable Sysmon Event ID 13 to collect registry modification events, which are necessary for the Sigma rule to function (`SmartScreenDisabledViaRegistry`).
*   Investigate any detected instances of SmartScreen being disabled to determine if the activity is malicious.
*   Implement strict access controls to prevent unauthorized users from modifying registry settings.
*   Regularly review and audit registry settings to ensure that SmartScreen is enabled and functioning correctly.
*   Deploy the Sigma rule in this brief to your SIEM and tune for your environment.
