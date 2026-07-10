---
title: Microsoft Defender 'Block at First Seen' Feature Disabled
slug: 2024-01-03-defender-block-disable
description: An attacker disables the Microsoft Defender 'Block at First Seen' feature to allow potentially malicious files to execute without initial scrutiny, increasing the risk of malware infection and data compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defender
  - malware
  - block-at-first-seen
  - registry
  - powershell
vendors:
  - Microsoft
products:
  - Microsoft Defender
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/disable_defender_blockatfirstseen_feature.yml
rules:
  - title: Detect Suspicious Defender Registry Modification
    description: Detects attempts to modify the Windows Defender registry keys to disable or weaken security features.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Suspicious PowerShell Defender Configuration
    description: Detects PowerShell commands used to disable or modify Windows Defender settings.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1059.001
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to disable the Microsoft Defender 'Block at First Seen' feature to bypass initial security checks and execute potentially malicious files. This feature is designed to send unknown files to Microsoft's cloud for analysis, blocking execution until a determination is made. Disabling this feature reduces the security posture of the system and allows malware to run without immediate scrutiny. While the specific method of disabling the feature isn't provided in the source, it's crucial to monitor for suspicious registry modifications or PowerShell commands that could achieve this. This brief focuses on detection strategies for identifying such attempts.

## Attack Chain

1. **Initial Access:** The attacker gains initial access to the system through an existing vulnerability, compromised credentials, or social engineering.
2. **Privilege Escalation:** If necessary, the attacker escalates privileges to gain administrative access to modify Defender settings.
3. **Disable 'Block at First Seen':** The attacker uses PowerShell or registry modifications to disable the 'Block at First Seen' feature. This may involve modifying the `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpCloudBlockLevel` registry key.
4. **Malware Execution:** With the feature disabled, the attacker executes a malicious file (e.g., a trojan or ransomware payload).
5. **Persistence:** The malware establishes persistence through registry keys, scheduled tasks, or other mechanisms to ensure it remains active after system restarts.
6. **Lateral Movement:** The attacker attempts to move laterally to other systems on the network, exploiting trust relationships or using stolen credentials.
7. **Data Exfiltration / Encryption:** The attacker exfiltrates sensitive data or encrypts files for ransom, depending on the attacker's objectives.

## Impact

Disabling 'Block at First Seen' significantly increases the risk of malware infection. If successful, attackers can execute malicious code without immediate detection, potentially leading to data theft, system compromise, or ransomware attacks. The impact can range from individual machine infections to widespread network compromise, depending on the attacker's goals and capabilities.

## Recommendation

*   Monitor for registry modifications related to disabling Defender's cloud-delivered protection using the "Detect Suspicious Defender Registry Modification" Sigma rule.
*   Detect suspicious PowerShell commands attempting to disable real-time monitoring or cloud-delivered protection using the "Detect Suspicious PowerShell Defender Configuration" Sigma rule.
*   Investigate any unexpected changes to Microsoft Defender's configuration.
