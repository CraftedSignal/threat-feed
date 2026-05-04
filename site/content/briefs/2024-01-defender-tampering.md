---
title: Microsoft Defender Tampering via Registry Modification
slug: 2024-01-defender-tampering
description: Adversaries may disable or tamper with Microsoft Defender features via registry modifications to evade detection and conceal malicious behavior on Windows systems.
date: "2024-01-03T12:00:00Z"
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
  - Trend Micro
  - Elastic
  - CrowdStrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Microsoft Defender
  - Elastic Defend
  - Elastic Endgame
  - Trend Micro Security Agent
affected_os:
  - Windows
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
  - title: Microsoft Windows Defender Tampering - Disable Realtime Monitoring
    description: Detects attempts to disable Microsoft Defender Realtime Monitoring via registry modification.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Microsoft Windows Defender Tampering - Disable Tamper Protection
    description: Detects attempts to disable Microsoft Defender Tamper Protection via registry modification.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers commonly disable or tamper with Microsoft Defender features to evade detection and conceal malicious behavior within compromised Windows environments. This is often achieved by modifying specific registry keys that control the behavior and functionality of Defender components, such as real-time monitoring, exploit protection, and tamper protection itself. Such actions can significantly reduce the effectiveness of endpoint security, allowing malicious activities to proceed undetected. The references point to techniques that disable PUA protection, tamper protection, memory integrity, and real-time protection. This behavior is observed across various attack scenarios, including ransomware deployment and cryptocurrency mining campaigns.

## Attack Chain

1. Initial access is gained through an unspecified vector (e.g., phishing, exploitation of a vulnerability).
2. The attacker obtains elevated privileges on the system.
3. The attacker uses an administrative tool like `reg.exe` or PowerShell to modify the registry.
4. The attacker disables real-time monitoring by setting `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring` to 1.
5. The attacker disables tamper protection by setting `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features\TamperProtection` to 0.
6. The attacker disables PUA Protection by setting `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\PUAProtection` to 0.
7. With Defender weakened, the attacker executes malicious payloads, such as ransomware or cryptocurrency miners.

## Impact

Successful tampering with Microsoft Defender can lead to a significant degradation of endpoint security posture. This can result in undetected malware infections, data breaches, and system compromise. Disabling Defender features can allow attackers to establish persistence, escalate privileges, and deploy malicious payloads without triggering alerts. The impact can range from individual system compromise to widespread network infection, depending on the attacker's objectives and the extent of the tampering.

## Recommendation

*   Deploy the Sigma rule "Microsoft Windows Defender Tampering - Disable Realtime Monitoring" to your SIEM to detect modifications to the `DisableRealtimeMonitoring` registry value.
*   Deploy the Sigma rule "Microsoft Windows Defender Tampering - Disable Tamper Protection" to detect modifications to the `TamperProtection` registry value.
*   Monitor registry modification events, specifically targeting keys associated with Microsoft Defender settings as described in the rule query.
*   Investigate any process modifying Windows Defender registry settings that are not explicitly authorized, referencing the process exclusions in the rule query.
