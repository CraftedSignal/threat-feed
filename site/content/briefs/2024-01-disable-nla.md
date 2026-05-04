---
title: Network-Level Authentication (NLA) Disabled via Registry Modification
slug: 2024-01-disable-nla
description: Adversaries may disable Network-Level Authentication (NLA) by modifying specific registry keys to bypass authentication requirements for Remote Desktop Protocol (RDP) and enable persistence mechanisms.
date: "2024-01-31T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - lateral-movement
  - registry-modification
  - windows
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - Elastic Endgame
  - SentinelOne Cloud Funnel
  - Sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/
rules:
  - title: Detect NLA Disabled via Registry Modification
    description: Detects attempts to disable Network-Level Authentication by modifying the UserAuthentication registry value.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1021
      - T1562
    data_sources:
      - registry_set
      - windows
  - title: Detect NLA Disabled via Registry Modification - Sysmon
    description: Detects attempts to disable Network-Level Authentication by modifying the UserAuthentication registry value using Sysmon.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1021
      - T1562
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Network Level Authentication (NLA) is a security feature in Windows that requires users to authenticate before establishing a full RDP session, adding an extra layer of protection against unauthorized access. Attackers might attempt to disable NLA to gain access to the Windows sign-in screen without proper authentication. This tactic can facilitate the deployment of persistence mechanisms, such as leveraging Accessibility Features like Sticky Keys, or enable unauthorized remote access. This brief addresses the registry modifications associated with disabling NLA and provides detection strategies to identify such attempts. The references indicate that this technique is used in conjunction with other attacks for lateral movement within a compromised network.

## Attack Chain

1. Initial access to the system is gained (potentially via compromised credentials or vulnerability exploitation).
2. The attacker elevates privileges to modify system-level settings.
3. The attacker modifies the registry key `HKLM\SYSTEM\ControlSet*\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication` to disable NLA.
4. The `UserAuthentication` value is set to "0" or "0x00000000".
5. The attacker attempts to establish an RDP connection to the compromised system.
6. Due to the disabled NLA, the attacker bypasses the initial authentication screen.
7. The attacker leverages accessibility features (e.g., Sticky Keys) for persistence or further exploitation.
8. The attacker gains unauthorized access to the system.

## Impact

Successful disabling of NLA allows attackers to bypass authentication and gain unauthorized access to systems via RDP. This can lead to data theft, malware installation, or further lateral movement within the network. While the exact number of victims and sectors targeted are unspecified, the potential impact includes significant data breaches and system compromise.

## Recommendation

*   Enable Sysmon process-creation and registry event logging to detect the registry modifications (Elastic Defend, Elastic Endgame, Microsoft Defender XDR, SentinelOne, Sysmon).
*   Deploy the Sigma rule provided to detect attempts to modify the `UserAuthentication` registry key (Sysmon Registry Events).
*   Review and harden RDP configurations across the environment to prevent unauthorized access (Microsoft documentation).
*   Monitor endpoint security policies to detect unauthorized registry modifications (Endpoint Security Policies).
