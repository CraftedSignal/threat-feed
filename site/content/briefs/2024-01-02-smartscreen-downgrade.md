---
title: Windows Defender SmartScreen Level Downgrade to 'Warn'
slug: 2024-01-02-smartscreen-downgrade
description: This analytic detects modifications to the Windows Registry to set Windows Defender SmartScreen level to 'Warn', which can reduce user suspicion and increase the risk of malware execution.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - registry-modification
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Windows Defender SmartScreen
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Detect SmartScreen Downgrade via Registry Modification
    description: Detects modifications to the Windows registry that set the Windows Defender SmartScreen level to 'warn'.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Process Modifying SmartScreen Registry Key
    description: Detects a process that attempts to modify the Windows Defender SmartScreen registry key.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying attempts to weaken Windows Defender SmartScreen by modifying registry settings. SmartScreen is a security feature designed to protect users from malicious websites and files. Attackers may attempt to lower the protection level to "Warn" from its default settings to reduce user suspicion when running potentially malicious executables. This allows malware to execute with a warning prompt, increasing the chances of successful deployment. This activity is often part of a broader defense evasion strategy employed after initial access has been gained. The detection specifically monitors changes to the `ShellSmartScreenLevel` registry value.

## Attack Chain

1.  Attacker gains initial access to the system, typically through phishing or exploiting a vulnerability.
2.  The attacker executes a process with elevated privileges (e.g., via UAC bypass) to modify the registry.
3.  The process modifies the registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ShellSmartScreenLevel` or `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ShellSmartScreenLevel`.
4.  The registry value `ShellSmartScreenLevel` is set to "Warn".
5.  The modified registry setting takes effect, causing SmartScreen to only display a warning when a potentially malicious executable is run.
6.  The attacker executes a malicious executable that would normally be blocked by SmartScreen.
7.  SmartScreen displays a warning prompt instead of blocking the execution.
8.  The user, less suspicious due to the less severe warning, allows the executable to run, leading to system compromise.

## Impact

Successful modification of the SmartScreen level can lead to a compromised system. If a user is tricked into running malware due to the less stringent warning, attackers can achieve code execution, persistence, and further lateral movement within the network. This can result in data theft, ransomware deployment, or other malicious activities. While specific victim counts are unavailable, the impact can be significant depending on the targeted environment.

## Recommendation

*   Enable Sysmon Event ID 13 logging to monitor registry modifications (as per the data_source in the rule).
*   Deploy the Sigma rule `Detect SmartScreen Downgrade via Registry Modification` to your SIEM and tune for your environment.
*   Investigate any detected instances of `ShellSmartScreenLevel` being set to "Warn" to determine if the activity is malicious.
*   Block processes attempting to modify the `ShellSmartScreenLevel` registry value using endpoint detection and response (EDR) tools (based on the Registry.registry_path in the rule).
