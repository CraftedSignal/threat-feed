---
title: PowerShell Used to Disable Windows Defender Security Monitoring
slug: 2024-01-powershell-disable-security-monitoring
description: Attackers are using PowerShell commands with specific Set-MpPreference parameters to disable Windows Defender's real-time behavior monitoring, a common tactic for malware to evade detection and persist on compromised systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - powershell
  - windows-defender
  - defense-evasion
  - endpoint
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
  - title: Detect PowerShell Disabling Real-time Monitoring
    description: Detects PowerShell commands that disable Windows Defender real-time monitoring using Set-MpPreference.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Disabling Behavior Monitoring
    description: Detects PowerShell commands that disable Windows Defender behavior monitoring.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Disabling Cloud Block Level
    description: Detects PowerShell commands that disable Windows Defender cloud block level using Set-MpPreference.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers are leveraging PowerShell to disable real-time security monitoring features in Windows Defender. This tactic involves using the `Set-MpPreference` cmdlet with specific parameters to turn off key security features like archive scanning, behavior monitoring, and real-time monitoring. This is often employed by malware, including Remote Access Trojans (RATs), bots, and Trojans, to evade antivirus detection. Disabling these protections allows attackers to operate undetected, potentially leading to data exfiltration, further system compromise, or the establishment of persistent access within the environment. The commands are often obfuscated or combined with other techniques to make detection more difficult. This activity represents a significant threat to organizations relying on Windows Defender for endpoint protection.

## Attack Chain

1.  Initial Access: The attacker gains initial access to the system through various means, such as exploiting a vulnerability or using compromised credentials.
2.  Privilege Escalation: The attacker escalates privileges to gain necessary permissions to execute PowerShell commands that can modify Windows Defender settings.
3.  Defense Evasion: The attacker executes PowerShell with `Set-MpPreference` to disable security features like `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, or `DisableIOAVProtection`.
4.  Configuration Changes: Windows Defender's real-time monitoring and other security features are disabled, reducing the system's ability to detect malicious activities.
5.  Malware Deployment: With security monitoring disabled, the attacker deploys malware, such as RATs, bots, or Trojans, onto the system without immediate detection.
6.  Persistence: The attacker establishes persistence mechanisms to maintain access to the compromised system, potentially using scheduled tasks or registry modifications.
7.  Lateral Movement: The attacker moves laterally within the network, compromising additional systems and expanding their reach.
8.  Data Exfiltration or Impact: The attacker exfiltrates sensitive data or carries out other malicious activities, such as deploying ransomware, while remaining undetected due to the disabled security monitoring.

## Impact

Successful execution of these PowerShell commands results in disabling Windows Defender's real-time protection and other security features. This can lead to undetected malware infections, data breaches, and system compromise. Organizations relying solely on Windows Defender are particularly vulnerable. The impact can range from individual workstation compromise to widespread network infection and significant data loss, depending on the attacker's objectives and the extent of their lateral movement.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect PowerShell commands attempting to disable Windows Defender features, and tune them for your environment.
*   Monitor process creation events (Sysmon Event ID 1 or Windows Event Log Security 4688) for PowerShell processes executing `Set-MpPreference` with parameters known to disable security features, as outlined in the Sigma rules.
*   Implement strict PowerShell execution policies to restrict the execution of unsigned or untrusted scripts, mitigating the risk of malicious PowerShell commands being executed.
*   Regularly review and audit Windows Defender settings to ensure that security features are enabled and functioning correctly, preventing unauthorized modifications.
*   Educate users about the risks of running untrusted PowerShell scripts and the importance of reporting suspicious activities.
