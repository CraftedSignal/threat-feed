---
title: Persistence via Hidden Run Key
slug: 2024-01-hidden-run-key-persistence
description: Adversaries achieve persistence by creating hidden, null-terminated registry keys within common Run key locations, evading standard system utilities.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - registry
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1106
    technique_name: Native API
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
references:
  - https://github.com/outflanknl/SharpHide
  - https://github.com/ewhitehats/InvisiblePersistence/blob/master/InvisibleRegValues_Whitepaper.pdf
rules:
  - title: Detect Hidden Run Key Creation
    description: Detects the creation of a registry value with a null-terminated name under Run keys, indicative of a persistence attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.001
      - T1564
    data_sources:
      - registry_set
      - windows
  - title: Detect Suspicious Process Launch via Registry Run Key
    description: Detects processes launched from non-standard locations via registry run keys, indicating potential malicious persistence.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies a persistence mechanism where adversaries use the NtSetValueKey native API to create hidden registry keys. These keys are crafted with null termination, rendering them invisible to typical system utilities like Registry Editor (regedit). The technique allows malicious programs to execute upon system startup or user logon, while remaining concealed from conventional detection methods. The scope of this threat includes any Windows system where unauthorized persistence is a concern, as attackers can leverage this method to maintain access and control over compromised machines. This technique has been observed being tested since at least 2020, and can be implemented using tools like SharpHide.

## Attack Chain

1.  An attacker gains initial access to the target system (e.g., through exploiting a vulnerability or using compromised credentials).
2.  The attacker uses a tool or script (e.g., SharpHide) to interact with the Windows Registry.
3.  The tool utilizes the NtSetValueKey native API to create a new registry value under a Run key path.
4.  The registry value's name is crafted with a null terminator, effectively hiding it from standard registry tools.
5.  The registry value data contains the path to a malicious executable or script.
6.  Upon system startup or user logon, the hidden registry value is processed by Windows.
7.  The malicious executable or script is launched, granting the attacker code execution and persistence.
8.  The attacker maintains persistent access to the compromised system, enabling further malicious activities like data theft or lateral movement.

## Impact

Successful exploitation leads to persistent access on the compromised system. The hidden nature of the registry keys makes detection and removal difficult. A successful attack allows the adversary to maintain a foothold even after system reboots. The number of potential victims is vast, encompassing any Windows system where attackers can gain initial access. This can affect organizations of any size across all sectors.

## Recommendation

*   Monitor registry modifications within common Run key paths for null-terminated value names to identify potential persistence attempts (see Sigma rule `Detect Hidden Run Key Creation`).
*   Enable Sysmon event ID 12 and 13 (RegistryEvent) to collect registry modification events, providing the necessary data for detection (Log Source: Sysmon).
*   Regularly audit and review registry Run key entries for suspicious or unknown executables to detect existing hidden persistence mechanisms.
*   Deploy the EQL rule provided in this brief and tune it for your environment, considering legitimate software installations or updates that may create similar registry keys (Rule: Persistence via Hidden Run Key Detected).
*   Implement strict access controls to prevent unauthorized registry modifications, limiting the ability of attackers to create hidden Run key entries.
*   Block the execution of unsigned or untrusted executables in the registry Run keys to prevent the activation of malicious payloads (Sysmon Event ID 1).
