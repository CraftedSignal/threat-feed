---
title: Windows Scheduled Tasks AT Command Enabled via Registry Modification
slug: 2024-01-at-command-enabled
description: Attackers may enable the deprecated Windows scheduled tasks AT command via registry modification to achieve local persistence or lateral movement on a compromised system.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense_evasion
  - execution
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-scheduledjob
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/001/
  - https://attack.mitre.org/techniques/T1053/
  - https://attack.mitre.org/techniques/T1053/002/
rules:
  - title: Detect AT Command Enablement via Registry
    description: Detects attempts to enable the Windows AT command by monitoring changes to the EnableAt registry value.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1053.002
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect AT Command Usage
    description: Detects the use of the AT command to schedule tasks.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1053.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows AT command, a legacy task scheduler, has been deprecated since Windows 8 and Windows Server 2012, yet remains for backward compatibility. Attackers can abuse this command to schedule malicious tasks for local persistence or lateral movement. This involves modifying the registry to enable the AT command, specifically targeting the `EnableAt` value. Successful exploitation allows adversaries to execute commands or programs at specified times, even after a system reboot. This threat is relevant because it leverages a legitimate, but outdated, system feature to bypass modern security controls.

## Attack Chain

1. An attacker gains initial access to a Windows system through some means (e.g., compromised credentials, software vulnerability).
2. The attacker attempts to modify the registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration`.
3. Specifically, the attacker changes the `EnableAt` value within the registry key.
4. The attacker sets the `EnableAt` value to "1" or "0x00000001" to enable the AT command.
5. The attacker uses the `at` command to schedule a malicious task to execute at a specific time.
6. The scheduled task executes, potentially running a malicious script or program.
7. This can lead to persistence, where the malicious task is re-executed after a reboot, or lateral movement, where the attacker uses the compromised system to access other systems on the network.

## Impact

Enabling the AT command allows attackers to schedule malicious tasks, leading to persistent access, privilege escalation, or lateral movement within the network. While the exact number of victims is unknown, successful exploitation can lead to significant data breaches, system compromise, and disruption of services. This is especially critical in environments where legacy applications rely on the AT command for task scheduling.

## Recommendation

*   Deploy the Sigma rule `Detect AT Command Enablement via Registry` to detect registry modifications related to enabling the AT command and tune for your environment.
*   Monitor process creation events for usage of the `at` command, focusing on unusual or unexpected processes spawned by it.
*   Regularly review and audit scheduled tasks to identify and remove any suspicious entries created by the `at` command.
*   Disable the AT command completely if it is not required for legitimate business purposes.
