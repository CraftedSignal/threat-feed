---
title: Network-Level Authentication (NLA) Disabled via Registry Modification
slug: 2024-01-disable-nla
description: Detection of attempts to disable Network-Level Authentication (NLA) by modifying the registry on Windows systems, potentially enabling persistence methods and unauthorized access.
date: "2024-01-25T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - lateral-movement
  - windows
  - registry-modification
vendors:
  - Microsoft
products:
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
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/
  - https://attack.mitre.org/techniques/T1112/
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/010/
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1021/001/
  - https://attack.mitre.org/tactics/TA0005/
  - https://attack.mitre.org/tactics/TA0008/
rules:
  - title: Detect NLA Disabled via Registry
    description: Detects when Network-Level Authentication (NLA) is disabled via registry modification by setting UserAuthentication to 0
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
  - title: Detect NLA Disabled via Registry (Alternate Path)
    description: Detects when Network-Level Authentication (NLA) is disabled via registry modification in an alternate registry path.
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

This threat brief focuses on the detection of unauthorized attempts to disable Network-Level Authentication (NLA) on Windows systems. NLA is a security feature that requires users to authenticate before a Remote Desktop Protocol (RDP) session is fully established, adding a layer of protection against unauthorized access. Attackers might disable NLA to bypass this authentication requirement, enabling various persistence mechanisms, particularly those leveraging Accessibility Features like Sticky Keys, which can grant access to the system without valid credentials. This activity is often associated with lateral movement and defense evasion tactics. The rule identifies registry modifications to the `UserAuthentication` value within specific registry paths related to RDP configuration. Disabling NLA makes the system more vulnerable to unauthorized access and potential compromise.

## Attack Chain

1.  Initial access to the target system through compromised credentials or an existing vulnerability (not covered in source).
2.  The attacker gains a foothold and establishes a command-and-control (C2) channel (not covered in source).
3.  The attacker attempts to disable Network-Level Authentication (NLA) by modifying the `UserAuthentication` registry value.
4.  The registry key `HKLM\SYSTEM\ControlSet*\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication` or similar is targeted.
5.  The `UserAuthentication` value is changed to "0" or "0x00000000" to disable NLA.
6.  The attacker leverages the disabled NLA to enable persistence mechanisms, such as utilizing Accessibility Features like Sticky Keys.
7.  The attacker gains unauthorized access to the Windows sign-in screen without proper authentication.
8.  The attacker achieves persistence and maintains unauthorized access to the compromised system.

## Impact

Disabling NLA significantly weakens the security posture of Windows systems, making them more susceptible to unauthorized access and lateral movement. Successful exploitation can lead to credential theft, data exfiltration, and the deployment of ransomware. While the number of affected systems and sectors are not specified, the impact is widespread as it affects any Windows system with RDP enabled.

## Recommendation

*   Deploy the Sigma rule "Detect NLA Disabled via Registry" to your SIEM and tune for your environment to detect the modification of the `UserAuthentication` registry value (see rule below).
*   Monitor registry modification events related to RDP configuration using Sysmon or other endpoint detection and response (EDR) solutions to detect potential NLA disabling attempts.
*   Review and update endpoint security policies to ensure that registry changes related to NLA are monitored and alerts are generated for any unauthorized modifications, as described in the overview section.
*   Investigate any alerts generated by the Sigma rules, focusing on identifying the user account and process responsible for the registry modification, as outlined in the triage steps.
