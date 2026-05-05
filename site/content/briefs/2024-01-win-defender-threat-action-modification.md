---
title: Windows Defender Threat Action Modification via Registry
slug: 2024-01-win-defender-threat-action-modification
description: An attacker modifies the Windows Defender ThreatSeverityDefaultAction registry setting to weaken defenses, potentially leading to unaddressed threats and system compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - endpoint
  - registry
  - defense-evasion
vendors:
  - Microsoft
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Windows Defender Threat Action Modification via Registry
    description: Detects modifications to the Windows Defender ThreatSeverityDefaultAction registry setting.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Process Modifying Windows Defender Threat Action Registry
    description: Detects processes modifying Windows Defender ThreatSeverityDefaultAction registry setting other than known legitimate processes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers may attempt to modify the Windows Defender ThreatSeverityDefaultAction registry setting to impair or disable the system's defense mechanisms. By altering this setting, adversaries can potentially allow threats to go unaddressed, bypassing antivirus protections. Observed registry value data includes "0x00000001" and "9". This technique can be employed following initial access to escalate privileges or establish persistence. This matters for defenders because a compromised Windows Defender configuration can lead to an increased risk of data compromise or further system exploitation.

## Attack Chain

1.  The attacker gains initial access to the system through unspecified means.
2.  The attacker obtains necessary privileges (e.g., via exploitation or credential theft) to modify the registry.
3.  The attacker modifies the `HKLM\SOFTWARE\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction` registry key.
4.  The attacker sets the registry value data to either "0x00000001" or "9" which changes the default action Windows Defender takes on detecting threats.
5.  Windows Defender's response to detected threats is altered based on the modified registry settings.
6.  The modified Windows Defender settings allow malware or other threats to execute without being blocked or remediated.

## Impact

Successful modification of the Windows Defender threat action can lead to a significant degradation of endpoint security. If successful, malware or other threats may execute without being blocked or remediated by Windows Defender. The potential impact includes data compromise, system exploitation, and persistent threats within the environment.

## Recommendation

*   Enable Sysmon Event ID 13 logging to monitor registry modifications (data_source).
*   Deploy the provided Sigma rule to detect modifications to the Windows Defender ThreatSeverityDefaultAction registry setting (rules).
*   Investigate any detected modifications to the specified registry path and values to determine if they are authorized (rules).
*   Use the filter macro to tune the provided Sigma rule for your specific environment (known_false_positives).
