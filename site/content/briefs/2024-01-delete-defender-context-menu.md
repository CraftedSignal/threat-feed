---
title: Windows Defender Context Menu Deletion Attempt
slug: 2024-01-delete-defender-context-menu
description: An attacker attempts to disable Windows Defender by deleting its context menu entry from the registry, a tactic often used by Remote Access Trojans (RATs) to impair defenses and facilitate further malicious activities.
date: "2024-01-03T18:15:00Z"
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
products:
  - Windows Defender
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/
  - https://app.any.run/tasks/45f5d114-91ea-486c-ab01-41c4093d2861/
rules:
  - title: Detect Windows Defender Context Menu Deletion via Registry
    description: Detects the deletion of the Windows Defender context menu entry from the registry, often associated with malware attempting to disable security features.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Process Modifying Windows Defender Context Menu Registry
    description: Detects processes that are deleting Windows Defender context menu entries via registry modification.
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

This threat brief describes the detection of a suspicious registry modification where the Windows Defender context menu entry is deleted. This activity is often associated with Remote Access Trojans (RATs) attempting to disable security features on compromised systems. Attackers commonly employ this technique to impair defenses, paving the way for subsequent malicious actions like unauthorized access, persistence establishment, and data exfiltration. Malware such as Lazyscripter, as documented by Malwarebytes, employs similar techniques to deploy double RATs. This activity is significant for defenders as it represents a direct attempt to weaken the security posture of the system, making it more vulnerable to further compromise.

## Attack Chain

1.  The attacker gains initial access to the system (likely through phishing or exploitation of a vulnerability, though the source does not specify).
2.  The attacker executes a script or program with elevated privileges.
3.  The script or program interacts with the Windows Registry.
4.  The script targets the registry key associated with the Windows Defender context menu: "*\\shellex\\ContextMenuHandlers\\EPP".
5.  The script or program deletes the targeted registry key or value.
6.  The Windows Defender context menu entry is removed, preventing users from easily accessing and managing Windows Defender through the right-click menu.
7.  With Windows Defender's context menu removed, the attacker can more easily perform further actions without user intervention.
8.  The attacker proceeds with persistence, lateral movement, or data exfiltration.

## Impact

Successful removal of the Windows Defender context menu impairs the user's ability to quickly manage Windows Defender via the right-click context menu, effectively weakening the endpoint's defenses. This can lead to a broader compromise of the system, including data theft, installation of ransomware, or use of the system as a staging ground for further attacks within the network. While the exact number of victims is unknown, this technique can be used against a wide range of Windows systems.

## Recommendation

*   Deploy the provided Sigma rule to detect the deletion of the Windows Defender context menu entry in the registry.
*   Enable Sysmon EventID 13 to collect the necessary registry event data for the Sigma rule to function.
*   Investigate any detected instances of this activity for potential malware infections (reference: Sigma rule detecting registry deletion).
*   Monitor for processes making changes to the registry path "*\\shellex\\ContextMenuHandlers\\EPP" (reference: Sigma rule and the associated registry path).
*   Review and harden endpoint security policies to prevent unauthorized registry modifications (reference: Sysmon EventID 13 for registry events).
