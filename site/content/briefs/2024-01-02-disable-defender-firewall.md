---
title: Windows Defender Firewall and Network Protection Disabled via Registry Modification
slug: 2024-01-02-disable-defender-firewall
description: An attacker modifies the Windows registry to disable the Windows Defender Firewall and Network Protection settings, potentially weakening the system's security posture and increasing vulnerability to further attacks.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender Security Center
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
  - title: Detect Defender Firewall UILockdown Modification
    description: Detects modifications to the Windows registry to disable Windows Defender Firewall and Network Protection settings.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Process Modifying Firewall UILockdown
    description: Detects a process that modifies the Windows registry to disable Windows Defender Firewall UILockdown.
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

This threat brief addresses a technique where attackers attempt to disable Windows Defender Firewall and Network Protection by modifying the `UILockdown` registry value. This attack aims to impair system defenses, restricting users from modifying crucial security settings. The original Splunk analytic was published on 2026-05-05, but this brief reflects current threat landscape awareness. The modification of the `UILockdown` registry value prevents users from accessing and altering firewall or network protection configurations, thereby creating a blind spot for defenders. Successful exploitation of this technique allows adversaries to perform malicious activities without triggering built-in firewall rules or network protections. This tactic is often observed in post-exploitation scenarios, enabling adversaries to establish persistence, move laterally, or exfiltrate sensitive data without hindrance.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the target system through various means (e.g., phishing, exploitation of vulnerabilities).
2.  **Privilege Escalation (Optional):** If necessary, the attacker escalates privileges to obtain the required permissions to modify the registry.
3.  **Registry Modification:** The attacker modifies the `UILockdown` registry value under `*\Windows Defender Security Center\Firewall and network protection\` to `0x00000001`. This action effectively disables the user interface elements related to firewall and network protection settings.
4.  **Defense Evasion:** With the firewall and network protection settings locked down, the attacker bypasses these security controls.
5.  **Lateral Movement:** The attacker leverages the compromised system to move laterally within the network, targeting other systems or resources.
6.  **Command and Control:** The attacker establishes a command and control (C2) channel to remotely control the compromised system and execute commands.
7.  **Data Exfiltration:** The attacker exfiltrates sensitive data from the compromised system or network to an external location.
8.  **Impact:** The attacker achieves their final objective, such as data theft, system disruption, or financial gain.

## Impact

Successful execution of this attack can lead to significant damage, including data breaches, financial losses, and reputational damage. By disabling Windows Defender Firewall and Network Protection, attackers can freely move within the network, exfiltrate sensitive data, and deploy ransomware without being detected by standard security measures. While specific victim counts and sectors are not available, this technique is widely applicable across various industries and organizations relying on Windows-based systems.

## Recommendation

*   Enable Sysmon EventID 13 logging to monitor registry modifications as indicated in the data source section of the provided source.
*   Deploy the Sigma rule `Detect Defender Firewall UILockdown Modification` to your SIEM and tune it for your environment.
*   Investigate any endpoint exhibiting the registry modification behavior described in this brief.
*   Review and harden Group Policy settings to prevent unauthorized registry modifications, specifically targeting the `UILockdown` registry key.
