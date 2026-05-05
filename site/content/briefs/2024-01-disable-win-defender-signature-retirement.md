---
title: Windows Defender Signature Retirement Disabled via Registry Modification
slug: 2024-01-disable-win-defender-signature-retirement
description: An attacker disables Windows Defender's signature retirement feature by modifying a registry key, potentially reducing its effectiveness in detecting threats by allowing older, less relevant signatures to persist.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows-registry
  - windows-defender
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Windows Defender Signature Retirement Disabled
    description: Detects when the Windows Defender Signature Retirement feature is disabled by modifying the registry key.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Sysmon Event 13 - Windows Defender Signature Retirement Disabled
    description: Detects the disabling of Windows Defender Signature Retirement using Sysmon Event ID 13.
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

Attackers may attempt to disable Windows Defender's signature retirement mechanism to weaken the endpoint protection. This is achieved by modifying the `DisableSignatureRetirement` registry value. Disabling signature retirement can prevent Windows Defender from removing outdated antivirus signatures, potentially reducing its effectiveness in detecting threats. Attackers may use this technique to evade detection by ensuring older, less effective signatures remain active, thereby reducing the likelihood of detecting their malicious activities. The tactic is used as part of defense evasion strategies.

## Attack Chain

1.  The attacker gains initial access to the target system through unspecified means.
2.  The attacker elevates privileges to obtain the necessary permissions to modify the Windows Registry.
3.  The attacker uses a command-line tool like `reg.exe` or PowerShell to modify the registry.
4.  The attacker targets the specific registry key: `HKLM\SOFTWARE\Microsoft\Windows Defender\NIS\Consumers\IPS`.
5.  The attacker modifies the `DisableSignatureRetirement` registry value.
6.  The attacker sets the `DisableSignatureRetirement` value to `0x00000001` to disable the signature retirement feature.
7.  Windows Defender continues to use outdated signatures, which may be less effective against modern threats.
8.  The attacker executes malicious code, evading detection due to the weakened signature database.

## Impact

Disabling Windows Defender's signature retirement feature weakens the system's security posture. This allows outdated and less effective signatures to remain active, potentially leading to missed detections of newer threats. Successfully exploiting this vulnerability allows attackers to operate with reduced risk of detection, potentially leading to data breaches, malware infections, and other security incidents. The impact can affect individual endpoints as well as entire organizations relying on Windows Defender for primary threat protection.

## Recommendation

*   Deploy the provided Sigma rule to detect modifications to the `DisableSignatureRetirement` registry value (see rules).
*   Monitor Windows Registry events for unauthorized modifications to Windows Defender settings, specifically Event ID 13 from Sysmon (see rules and data_source).
*   Investigate any detected instances of `DisableSignatureRetirement` being set to `0x00000001` (see rules).
*   Implement strict access controls to prevent unauthorized modification of registry settings related to Windows Defender.
*   Tune the provided filter macro `windows_impair_defense_disable_win_defender_signature_retirement_filter` to reduce false positives in your environment (see search).
