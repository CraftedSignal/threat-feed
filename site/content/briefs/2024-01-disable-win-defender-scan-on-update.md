---
title: Windows Defender Scan On Update Disabled via Registry Modification
slug: 2024-01-disable-win-defender-scan-on-update
description: An attacker modifies the Windows registry to disable the Windows Defender Scan On Update feature, potentially evading detection and establishing persistence.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - registry-modification
  - windows-defender
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Registry Modification to Disable Windows Defender Scan On Update
    description: Detects modifications to the Windows registry that disable the Windows Defender Scan On Update feature.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Process Modifying Windows Defender DisableScanOnUpdate Registry Key
    description: Detects a process modifying the Windows Defender DisableScanOnUpdate registry key.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This threat brief addresses the disabling of Windows Defender's "Scan On Update" feature through registry modifications. Attackers may target this setting to prevent automatic scans when signature updates are applied, thereby hindering real-time detection of malware and other threats. This technique can be employed to evade initial access detection or to maintain persistence on a compromised system. Specifically, the attack involves changing the "DisableScanOnUpdate" registry value to "0x00000001". Disabling this feature, while not always indicative of malicious activity, significantly reduces the effectiveness of Windows Defender, making systems more susceptible to compromise. Defenders should monitor for unauthorized registry modifications related to Windows Defender settings.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., via phishing or exploiting a vulnerability).
2.  The attacker escalates privileges to obtain the necessary permissions to modify the registry.
3.  The attacker uses a command-line tool (e.g., `reg.exe`, PowerShell) or a script to modify the `DisableScanOnUpdate` registry value.
4.  The attacker changes the registry key `HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates\DisableScanOnUpdate` to a value of `0x00000001`.
5.  Windows Defender no longer performs automatic scans upon signature updates.
6.  The attacker deploys malware or other malicious payloads to the system without triggering immediate scans.
7.  The attacker establishes persistence and continues to perform malicious activities.

## Impact

Disabling the Windows Defender Scan On Update feature can significantly increase the dwell time of malware on a compromised system. This can lead to data breaches, system corruption, or further lateral movement within the network. The potential impact includes financial losses, reputational damage, and disruption of business operations. Systems that are not actively scanned are more vulnerable to both known and unknown threats, potentially impacting thousands of endpoints within an organization if the registry modification is widespread.

## Recommendation

*   Deploy the Sigma rule `Registry Modification to Disable Windows Defender Scan On Update` to detect registry modifications related to the `DisableScanOnUpdate` setting.
*   Monitor Sysmon EventID 13 for registry modifications to the `HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates\DisableScanOnUpdate` path.
*   Investigate any instances where the `DisableScanOnUpdate` registry value is set to `0x00000001`.
*   Use endpoint detection and response (EDR) solutions to identify and block suspicious processes attempting to modify Windows Defender settings.
*   Tune the `windows_impair_defense_disable_win_defender_scan_on_update_filter` macro in Splunk to reduce false positives.
