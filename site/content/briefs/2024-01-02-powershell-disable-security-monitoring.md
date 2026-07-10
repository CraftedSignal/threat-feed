---
title: PowerShell Used to Disable Windows Defender Security Monitoring
slug: 2024-01-02-powershell-disable-security-monitoring
description: This analytic identifies attempts to disable Windows Defender real-time behavior monitoring via PowerShell commands using `Set-MpPreference`, commonly used by malware to evade detection and potentially leading to data exfiltration or system compromise.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - powershell
  - windows-defender
vendors:
  - Microsoft
products:
  - Windows Defender
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md#atomic-test-15---tamper-with-windows-defender-atp-powershell
  - https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps
rules:
  - title: Powershell Disable Security Monitoring via Set-MpPreference
    description: Detects PowerShell commands that attempt to disable Windows Defender's real-time monitoring features using Set-MpPreference.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Powershell Disable PUA Protection
    description: Detects PowerShell commands that attempt to disable Windows Defender's PUAProtection feature using Set-MpPreference.
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

This brief focuses on the abuse of PowerShell to disable Windows Defender's security monitoring features. Attackers, including malware such as Remote Access Trojans (RATs), bots, and Trojans, leverage this technique to evade detection and establish a persistent foothold within compromised systems. The activity is detected by monitoring for specific `Set-MpPreference` parameters within PowerShell command lines that disable real-time monitoring, archive scanning, and other key security features. This allows attackers to operate undetected, potentially leading to data exfiltration, further system compromise, or persistent access within the environment. The technique is described in the Atomic Red Team test T1562.001.

## Attack Chain

1.  The attacker gains initial access to the system (potentially via phishing or exploiting a vulnerability).
2.  The attacker executes PowerShell with elevated privileges.
3.  PowerShell invokes the `Set-MpPreference` cmdlet to modify Windows Defender settings.
4.  Specific parameters like `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, or `DisableIOAVProtection` are used with a value of `$true` or `1`.
5.  Windows Defender's real-time monitoring and behavior analysis are disabled, reducing the system's defenses.
6.  The attacker deploys malware, such as a RAT, bot, or Trojan, to the compromised system.
7.  The malware operates without being detected by Windows Defender, performing actions like data exfiltration.
8.  The attacker maintains persistence on the system, potentially escalating privileges and moving laterally within the network.

## Impact

A successful attack can lead to complete compromise of the targeted system. Disabling Windows Defender allows malware to operate freely, resulting in data exfiltration, ransomware deployment, or the establishment of a persistent backdoor. The incident could affect individual workstations as well as critical servers within the network. This could lead to financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Deploy the Sigma rule `Powershell Disable Security Monitoring via Set-MpPreference` to detect PowerShell commands attempting to disable Windows Defender features (see `rules` section).
*   Enable Sysmon process creation logging (Event ID 1) and Windows Event Log Security Auditing (Event ID 4688) to provide necessary data for the detections.
*   Review and tune the `powershell_disable_security_monitoring_filter` macro to reduce false positives in your environment.
*   Investigate any alerts triggered by the Sigma rule, focusing on the `Processes.parent_process` and `Processes.user` to identify the source of the malicious activity.
*   Monitor endpoint processes for unusual PowerShell activity, specifically commands containing `Set-MpPreference` and related parameters.
