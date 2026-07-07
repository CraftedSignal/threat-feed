---
title: Suspicious Process Monitor Driver Creation by Non-Sysinternals Binary
slug: 2026-07-suspicious-procmon-driver-creation
description: This brief details a detection strategy for malicious actors attempting to establish persistence or elevate privileges by creating a Process Monitor driver file (`.sys`) from an unauthorized process, indicating potential kernel-level compromise on Windows systems.
date: "2026-07-03T14:17:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - windows
  - detection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The creation of a kernel driver, especially if designed to load at boot, is a common technique for establishing persistence.
    confidence_band: med
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Detects creation of the Process Monitor driver by processes other than Process Monitor (procmon) itself, indicating an attempt to gain higher privileges or maintain them.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_sysinternals_procmon_driver_susp_creation.yml
rules:
  - title: Process Monitor Driver Creation By Non-Sysinternals Binary
    description: Detects creation of the Process Monitor driver by processes other than Process Monitor (procmon) itself, indicating potential privilege escalation or persistence attempts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 1
---

This detection brief focuses on an unusual activity where a Process Monitor driver file (typically named `procmon*.sys`) is created by a binary other than the legitimate Sysinternals Process Monitor application itself (e.g., `procmon.exe`, `procmon64.exe`). While Process Monitor legitimately creates and loads its own kernel driver to function, its creation by an unexpected process is highly suspicious. This behavior suggests a potential attempt by malicious actors to achieve privilege escalation or establish stealthy persistence by installing a rogue kernel driver. Kernel-level access grants an attacker significant control over the operating system, allowing for defense evasion, rootkit functionality, and execution of arbitrary code with SYSTEM privileges, making this a critical behavior to monitor for on Windows endpoints.

## Attack Chain

1.  **Initial Access**: A malicious actor gains initial access to a Windows system, typically through a common vector such as a phishing campaign, exploiting a public-facing vulnerable service, or compromising user credentials.
2.  **Execution**: The attacker executes a malicious payload on the compromised system, often a loader or backdoor, establishing an initial foothold for further operations.
3.  **Privilege Escalation**: To achieve higher access, the attacker leverages a local privilege escalation exploit (e.g., a vulnerability in a Windows service or kernel component) or other techniques to gain SYSTEM-level privileges.
4.  **Driver Creation**: With elevated privileges, the attacker creates a `.sys` file (e.g., `procmon.sys` or a similarly named file) in a system directory from a process *other than* the legitimate Sysinternals Process Monitor binary (e.g., `cmd.exe`, `powershell.exe`, or a custom malicious executable).
5.  **Driver Installation/Loading**: The attacker then installs and loads this newly created, potentially malicious driver, often by manipulating registry keys (e.g., under `HKLM\SYSTEM\CurrentControlSet\Services`) or using legitimate Windows APIs, granting the attacker kernel-level control.
6.  **Persistence/Defense Evasion**: The successfully loaded kernel driver enables the attacker to maintain stealthy persistence across reboots, evade detection by security products, or perform highly privileged actions for data exfiltration, command and control, or further system compromise.

## Impact

If an attacker successfully creates and loads a malicious kernel driver through this technique, the impact can be severe. It grants them SYSTEM-level privileges and kernel-mode access, allowing them to operate with virtually unlimited control over the operating system. This can lead to complete system compromise, enabling rootkit functionality for defense evasion, persistent access that is difficult to remove, and the ability to exfiltrate sensitive data or deploy further malware undetected. This technique bypasses many user-mode security controls, posing a significant challenge for incident responders. While no specific victims or campaigns are identified, any organization running Windows systems could be targeted by actors employing such privilege escalation and persistence methods.

## Recommendation

*   Deploy the "Process Monitor Driver Creation By Non-Sysinternals Binary" Sigma rule to your SIEM for immediate detection of this suspicious activity.
*   Ensure comprehensive file event logging, such as with Sysmon, is enabled on all Windows endpoints to capture the `TargetFilename` and `Image` paths required by the rule.
*   Investigate all alerts generated by the "Process Monitor Driver Creation By Non-Sysinternals Binary" rule to determine if the driver creation is legitimate or indicative of malicious activity.
