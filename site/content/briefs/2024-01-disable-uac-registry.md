---
title: Disabling User Account Control via Registry Modification
slug: 2024-01-disable-uac-registry
description: Attackers may disable User Account Control (UAC) by modifying specific registry values, allowing them to execute code with elevated privileges, bypass security restrictions, and potentially escalate privileges on Windows systems.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Elastic
  - CrowdStrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.greyhathacker.net/?p=796
  - https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings
  - https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-overview
  - https://www.elastic.co/security-labs/dissecting-remcos-rat-part-four
rules:
  - title: UAC Disable via Registry Modification
    description: Detects changes to registry values that disable User Account Control (UAC).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1112
      - T1548.002
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: UAC Registry Bypass - EnableLUA
    description: Detects changes specifically to EnableLUA registry key
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1112
      - T1548.002
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

User Account Control (UAC) is a security feature in Windows that helps mitigate the impact of malware by requiring administrative privileges for certain actions. Attackers may attempt to disable or bypass UAC to execute code with elevated privileges without user consent. This is often achieved by modifying specific registry values related to UAC settings. The registry values include `EnableLUA`, `ConsentPromptBehaviorAdmin`, and `PromptOnSecureDesktop`. Successful modification of these values to `0` or `0x00000000` effectively disables UAC, allowing attackers to perform privileged actions without triggering UAC prompts. This technique has been observed in conjunction with malware such as the Remcos RAT.

## Attack Chain

1.  Initial Access: An attacker gains initial access to the system, possibly through phishing or exploiting a vulnerability.
2.  Privilege Escalation: The attacker attempts to escalate privileges to perform actions requiring administrative rights.
3.  Registry Modification: The attacker modifies the registry values `EnableLUA`, `ConsentPromptBehaviorAdmin`, and/or `PromptOnSecureDesktop` located under `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\`.
4.  Disable UAC: By setting these registry values to `0` or `0x00000000`, the attacker disables UAC.
5.  Code Execution: The attacker executes malicious code, leveraging the now-disabled UAC to bypass security restrictions.
6.  Persistence: The attacker establishes persistence, ensuring continued access to the compromised system.
7.  Lateral Movement: The attacker moves laterally to other systems within the network, leveraging the compromised system as a launchpad.
8.  Objective Completion: The attacker achieves their final objective, such as data exfiltration, system disruption, or ransomware deployment.

## Impact

Disabling UAC allows attackers to execute code with elevated privileges, bypassing security restrictions. This can lead to a complete compromise of the affected system, allowing attackers to install malware, modify system settings, steal sensitive data, and potentially move laterally to other systems within the network. The rule has a risk score of 47.

## Recommendation

*   Monitor registry modifications for changes to `EnableLUA`, `ConsentPromptBehaviorAdmin`, and `PromptOnSecureDesktop` with the Sigma rule provided.
*   Enable Sysmon registry event logging to capture registry modifications.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
