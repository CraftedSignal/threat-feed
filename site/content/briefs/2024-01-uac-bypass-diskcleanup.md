---
title: UAC Bypass via DiskCleanup Scheduled Task Hijack
slug: 2024-01-uac-bypass-diskcleanup
description: Attackers bypass User Account Control (UAC) by hijacking the DiskCleanup Scheduled Task to stealthily execute code with elevated permissions on Windows systems.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - uac-bypass
  - privilege-escalation
  - windows
  - diskcleanup
  - scheduled-task
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Defender XDR
  - Elastic Defend
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
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_uac_bypass_diskcleanup_hijack.toml
rules:
  - title: UAC Bypass via DiskCleanup with Suspicious Path
    description: Detects UAC bypass attempts by monitoring for DiskCleanup executions with suspicious arguments and paths.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1548.002
    data_sources:
      - process_creation
      - windows
  - title: UAC Bypass via DiskCleanup and Taskhostw
    description: Detects UAC bypass attempts by monitoring for DiskCleanup or Taskhostw executions with suspicious arguments.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1548.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule identifies User Account Control (UAC) bypass attempts via hijacking the DiskCleanup Scheduled Task. Attackers exploit this method to execute code with elevated privileges, bypassing standard security controls. The technique involves leveraging the `cleanmgr.exe` or `taskhostw.exe` executables with specific arguments (`/autoclean` and `/d`) outside of their expected paths. This allows attackers to run malicious code under the guise of a legitimate system process, making detection more challenging. This technique is used to gain elevated privileges on a compromised system, allowing for further malicious activities.

## Attack Chain

1. An attacker gains initial access to the system (e.g., via phishing or exploiting a software vulnerability).
2. The attacker modifies or creates a scheduled task to execute `cleanmgr.exe` or `taskhostw.exe` with the `/autoclean` and `/d` arguments.
3. The modified scheduled task is triggered, executing the specified executable with the supplied arguments.
4. The executable, such as `cleanmgr.exe`, attempts to run Disk Cleanup.
5. If the executable path is outside the standard locations (e.g., `C:\\Windows\\System32` or `C:\\Windows\\SysWOW64`), it indicates a potential hijack.
6. Malicious code is executed with elevated privileges due to the UAC bypass.
7. The attacker uses these elevated privileges to install malware, modify system settings, or perform other malicious activities.

## Impact

Successful exploitation allows attackers to bypass User Account Control (UAC) and execute code with elevated privileges. This can lead to the installation of malware, modification of system settings, data theft, and other malicious activities. While the exact number of victims is unknown, this technique is effective on systems where UAC is enabled but misconfigured or vulnerable.

## Recommendation

*   Deploy the Sigma rule "UAC Bypass via DiskCleanup with Suspicious Path" to your SIEM and tune for your environment to detect UAC bypass attempts.
*   Deploy the Sigma rule "UAC Bypass via DiskCleanup and Taskhostw" to your SIEM to detect UAC bypass attempts.
*   Monitor process creation events for `cleanmgr.exe` and `taskhostw.exe` with the `/autoclean` and `/d` arguments, focusing on executions outside the standard system directories.
*   Review and harden scheduled tasks to prevent unauthorized modifications.
*   Ensure that UAC settings are properly configured and enforced across the organization.
