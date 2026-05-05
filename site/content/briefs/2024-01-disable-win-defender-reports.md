---
title: Windows Defender Reporting Disabled via Registry Modification
slug: 2024-01-disable-win-defender-reports
description: Attackers modify the Windows registry to disable Windows Defender generic reports, preventing error reports and potentially hiding malicious activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - registry
vendors:
  - Microsoft
products:
  - Windows Defender
affected_os:
  - Windows 10
  - Windows 11
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Detect Windows Defender Reporting Disabled via Registry Modification
    description: Detects modifications to the Windows Registry that disable Windows Defender's generic reports.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Process Modifying Windows Defender Registry
    description: Detects processes like reg.exe or powershell.exe modifying Windows Defender related registry keys
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This analytic detects modifications to the Windows registry that disable Windows Defender's generic reports. Attackers may modify the "DisableGenericRePorts" registry value to prevent the transmission of error reports to Microsoft's Windows Error Reporting service, effectively hiding malicious activities from being reported. This technique can be employed to reduce the visibility of attacker actions and increase the likelihood of undetected system compromise by bypassing Windows Defender detections. The activity is identified through monitoring changes to specific registry keys associated with Windows Defender reporting. Disabling these reports hinders the ability to identify and respond to security incidents effectively.

## Attack Chain

1.  The attacker gains initial access to the target system (e.g., through compromised credentials or exploiting a vulnerability).
2.  The attacker elevates privileges to obtain the necessary permissions to modify the Windows Registry.
3.  The attacker uses a process (e.g., `reg.exe`, `powershell.exe`, or a custom script) to modify the registry.
4.  The process modifies the `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting\DisableGenericRePorts` registry value.
5.  The `DisableGenericRePorts` registry value is set to `0x00000001` (DWORD), disabling Windows Defender generic reports.
6.  Windows Defender no longer sends generic reports to the Windows Error Reporting service.
7.  Malicious activities on the system are less likely to be reported, allowing the attacker to operate with reduced visibility.

## Impact

Successful execution of this technique leads to a diminished ability to detect malicious activity on the affected system. Disabling Windows Defender's reporting mechanisms can allow malware or other malicious actors to operate undetected, potentially leading to data breaches, system compromise, or other adverse outcomes. The impact is significant because it impairs a key security control, creating a blind spot for defenders.

## Recommendation

*   Enable Sysmon EventID 13 logging to monitor registry modifications, as this is the data source for the provided detections.
*   Deploy the Sigma rule `Detect Windows Defender Reporting Disabled via Registry Modification` to your SIEM to detect this specific activity.
*   Investigate any detected instances of registry modifications to the `DisableGenericRePorts` value.
*   Monitor process creation events for processes such as `reg.exe` or `powershell.exe` modifying registry keys related to Windows Defender using the rule `Suspicious Process Modifying Windows Defender Registry`.
