---
title: Microsoft Defender Tampering via Registry Modification
slug: 2024-05-defender-tampering
description: Adversaries may disable or tamper with Microsoft Defender features to evade detection and conceal malicious behavior by modifying specific registry keys and values.
date: "2024-05-03T14:27:00Z"
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
products:
  - Microsoft Defender
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://www.tenforums.com/tutorials/32236-enable-disable-microsoft-defender-pua-protection-windows-10-a.html
  - https://www.tenforums.com/tutorials/104025-turn-off-core-isolation-memory-integrity-windows-10-a.html
  - https://www.tenforums.com/tutorials/105533-enable-disable-windows-defender-exploit-protection-settings.html
  - https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-microsoft-defender-antivirus.html
  - https://www.tenforums.com/tutorials/51514-turn-off-microsoft-defender-periodic-scanning-windows-10-a.html
  - https://www.tenforums.com/tutorials/3569-turn-off-real-time-protection-microsoft-defender-antivirus.html
  - https://www.tenforums.com/tutorials/99576-how-schedule-scan-microsoft-defender-antivirus-windows-10-a.html
  - https://www.elastic.co/security-labs/invisible-miners-unveiling-ghostengine
rules:
  - title: Microsoft Defender DisableAntiSpyware Registry Modification
    description: Detects modification of the DisableAntiSpyware registry value, which disables Microsoft Defender.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Microsoft Defender TamperProtection Registry Modification
    description: Detects modification of the TamperProtection registry value, which disables tamper protection in Microsoft Defender.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Microsoft Defender RealtimeMonitoring Disabled
    description: Detects modification of the DisableRealtimeMonitoring registry value, disabling real-time monitoring.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

Attackers frequently attempt to disable or modify Microsoft Defender settings to evade detection and maintain persistence within a compromised environment. This involves altering registry keys that control various Defender features, such as real-time monitoring, behavior monitoring, exploit protection, and tamper protection. By setting specific registry values to disable these features, attackers can significantly reduce the effectiveness of the built-in security measures, allowing them to execute malicious code and move laterally without being detected. This activity is commonly observed after initial access is gained, and before deploying more sophisticated payloads or establishing command and control. This type of behavior was observed in conjunction with IcedID and XingLocker ransomware, highlighting the importance of monitoring for these defense evasion attempts.

## Attack Chain

1. Initial Access: The attacker gains initial access to the target system, potentially through phishing or exploiting a vulnerability.
2. Privilege Escalation (if needed): The attacker escalates privileges to gain administrative access, enabling them to modify system settings.
3. Registry Modification: The attacker modifies specific registry keys to disable Microsoft Defender features. This includes keys related to real-time protection (DisableRealtimeMonitoring), behavior monitoring (DisableBehaviorMonitoring), and exploit protection (DisallowExploitProtectionOverride).
4. Disable Real-time Monitoring: The attacker sets the `DisableRealtimeMonitoring` registry value to 1 (or 0x00000001) under `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection`.
5. Disable Tamper Protection: The attacker sets the `TamperProtection` registry value to 0 (or 0x00000000) under `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features`.
6. Disable PUA Protection: The attacker sets the `PUAProtection` registry value to 0 (or 0x00000000) under `HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender`.
7. Payload Deployment: With Defender disabled, the attacker deploys malicious payloads such as malware, ransomware, or credential theft tools.
8. Lateral Movement: The attacker leverages the compromised system to move laterally within the network, targeting additional systems and data.

## Impact

Successful tampering of Microsoft Defender can lead to widespread malware infections, data breaches, and ransomware deployment. With Defender disabled, systems become vulnerable to a wide range of threats. This can result in significant financial losses, reputational damage, and operational disruption. The absence of real-time protection allows attackers to execute malicious code without immediate detection, increasing the dwell time and potential impact of the attack. In cases where ransomware is deployed, the entire organization's data can be encrypted, leading to significant downtime and recovery costs.

## Recommendation

*   Deploy the Sigma rule "Microsoft Windows Defender Tampering" to your SIEM to detect malicious registry modifications (see "rules" section).
*   Enable Sysmon process creation and registry event logging to provide necessary data for the Sigma rules to function.
*   Investigate any alerts generated by the Sigma rule by examining the process execution chain and validating the activity is not related to legitimate system administration tasks.
*   Review and enforce the principle of least privilege to limit the ability of users to modify critical system settings.
