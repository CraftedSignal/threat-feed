---
title: UAC Bypass via ICMLuaUtil Elevated COM Interface
slug: 2024-01-uac-bypass-icmluautil
description: Attackers attempt to bypass User Account Control (UAC) to stealthily execute code with elevated permissions by abusing the ICMLuaUtil Elevated COM interface, spawning processes from dllhost.exe with specific arguments.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - uac-bypass
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1559
    technique_name: Inter-Process Communication
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_uac_bypass_com_interface_icmluautil.toml
  - https://attack.mitre.org/techniques/T1548/
  - https://attack.mitre.org/techniques/T1548/002/
  - https://attack.mitre.org/techniques/T1559/
  - https://attack.mitre.org/techniques/T1559/001/
rules:
  - title: UAC Bypass via ICMLuaUtil COM - Suspicious Child Process
    description: Detects a child process spawned by dllhost.exe with specific arguments indicative of a UAC bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1548.002
      - T1559.001
    data_sources:
      - process_creation
      - windows
  - title: UAC Bypass via ICMLuaUtil COM - dllhost.exe with Suspicious Arguments
    description: Detects dllhost.exe spawning with arguments indicative of a UAC bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1548.002
      - T1559.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on the exploitation of the ICMLuaUtil Elevated COM interface to bypass User Account Control (UAC) on Windows systems. Attackers leverage this method to execute code with elevated privileges without triggering standard UAC prompts. The attack involves spawning processes from `dllhost.exe` with specific arguments related to the ICMLuaUtil interface. This technique allows malicious actors to gain higher-level access to the system, potentially leading to further compromise. Defenders should monitor process creation events for instances of `dllhost.exe` spawning child processes with the specific arguments, excluding legitimate processes like `WerFault.exe`, to detect potential UAC bypass attempts. The timeframe for this threat has been observed in rules updated as recently as April 7, 2026.

## Attack Chain

1.  The attacker gains initial access to the system through an unrelated vector (e.g., phishing, exploit).
2.  The attacker executes a payload designed to bypass UAC using the ICMLuaUtil COM interface.
3.  The payload spawns `dllhost.exe` with specific arguments, such as `/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` or `/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}`, to leverage the elevated COM interface.
4.  `dllhost.exe`, acting as a surrogate host process, executes the attacker's code with elevated privileges.
5.  The attacker's code performs malicious actions, such as installing malware, modifying system settings, or stealing credentials.
6.  The attacker leverages the elevated privileges to move laterally within the network.
7.  The attacker achieves their objective, such as data exfiltration or ransomware deployment.

## Impact

A successful UAC bypass allows attackers to execute code with elevated privileges without user consent, granting them significant control over the compromised system. This can lead to the installation of persistent malware, modification of security settings, theft of sensitive data, and lateral movement within the network. The impact ranges from individual system compromise to widespread organizational damage, depending on the attacker's objectives and the scope of the breach.

## Recommendation

*   Deploy the "UAC Bypass via ICMLuaUtil Elevated COM Interface" Sigma rule to your SIEM to detect exploitation attempts.
*   Monitor process creation events for instances of `dllhost.exe` spawning child processes with the arguments `/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` or `/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}` (as described in the Attack Chain) and filter out legitimate processes like `WerFault.exe`.
*   Enable Sysmon process creation logging to ensure visibility into process relationships and command-line arguments.
*   Implement application whitelisting to restrict the execution of unauthorized applications, focusing on blocking suspicious uses of `dllhost.exe`.
