---
title: UAC Bypass via DiskCleanup Scheduled Task Hijack
slug: 2024-01-uac-bypass-diskcleanup
description: Attackers bypass User Account Control (UAC) to stealthily execute code with elevated permissions by hijacking the DiskCleanup Scheduled Task, leveraging specific arguments with non-standard executables.
date: "2024-01-03T14:27:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - uac-bypass
  - privilege-escalation
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
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://attack.mitre.org/techniques/T1548/
  - https://attack.mitre.org/techniques/T1548/002/
  - https://attack.mitre.org/techniques/T1053/
  - https://attack.mitre.org/techniques/T1053/005/
rules:
  - title: UAC Bypass via DiskCleanup Scheduled Task Hijack
    description: Detects UAC bypass attempts by identifying processes using specific arguments with executables other than the legitimate DiskCleanup executables.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - privilege_escalation
    techniques:
      - T1053.005
      - T1548.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Execution with DiskCleanup Arguments
    description: This rule identifies processes running with arguments commonly associated with DiskCleanup, but originating from unusual locations.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - privilege_escalation
    techniques:
      - T1053.005
      - T1548.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat involves the exploitation of the Windows User Account Control (UAC) by hijacking the DiskCleanup scheduled task. The attack, observed in environments utilizing Windows operating systems, abuses the auto-elevation capabilities associated with the DiskCleanup utility. By manipulating or replacing the legitimate DiskCleanup executable with a malicious payload and using specific command-line arguments, attackers can bypass UAC and execute arbitrary code with elevated privileges. This allows for stealthy installation of malware, configuration changes, or other malicious activities. The detection rule provided identifies processes employing the `/autoclean` and `/d` arguments in conjunction with executables outside the standard DiskCleanup paths, aiming to uncover potential UAC bypass attempts. This technique is effective because DiskCleanup is a trusted Windows component, allowing it to run with elevated privileges without prompting the user.

## Attack Chain

1.  The attacker gains initial access to the system through a separate exploit or social engineering.
2.  The attacker identifies the DiskCleanup scheduled task as a UAC bypass target.
3.  The attacker places a malicious executable on the system.
4.  The attacker modifies the system to execute the malicious executable with the `/autoclean` and `/d` arguments. This might involve creating a new scheduled task or modifying an existing one.
5.  The modified or new scheduled task triggers the execution of the malicious executable, leveraging the auto-elevation of DiskCleanup.
6.  UAC is bypassed because the system trusts the DiskCleanup process.
7.  The malicious executable runs with elevated privileges, allowing the attacker to perform privileged actions.
8.  The attacker installs malware, modifies system settings, or performs other malicious activities.

## Impact

Successful exploitation of this UAC bypass technique allows attackers to execute code with elevated privileges, leading to a range of potential impacts. This can include the installation of persistent backdoors, the theft of sensitive data, or the complete compromise of the affected system. Since this technique bypasses security controls designed to limit privilege escalation, it significantly increases the attacker's ability to move laterally within a network and achieve their objectives. The impact is especially severe in environments where UAC is relied upon as a primary security mechanism.

## Recommendation

*   Deploy the Sigma rule "UAC Bypass via DiskCleanup Scheduled Task Hijack" to your SIEM and tune for your environment to detect suspicious process executions (rules).
*   Investigate any process executions flagged by the Sigma rule, paying close attention to the process arguments and executable paths (rules).
*   Enforce strict access control policies to limit the ability of users to modify scheduled tasks (attack chain).
*   Monitor process creation events for the execution of executables with the `/autoclean` and `/d` arguments, excluding legitimate DiskCleanup executables (rules).
*   Regularly review and audit scheduled tasks to identify any unauthorized or malicious tasks (attack chain).
