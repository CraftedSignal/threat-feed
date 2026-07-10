---
title: TelemetryController Scheduled Task Hijack for Persistence and Privilege Escalation
slug: 2024-01-telemetrycontroller-hijack
description: Adversaries can hijack the Microsoft Compatibility Appraiser scheduled task (TelemetryController) to establish persistence and escalate privileges by executing arbitrary code with system-level permissions.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - privilege-escalation
  - scheduled-task
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence
  - https://attack.mitre.org/techniques/T1053/
  - https://attack.mitre.org/techniques/T1053/005/
  - https://attack.mitre.org/techniques/T1574/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: TelemetryController Scheduled Task Hijack - Suspicious Process
    description: Detects suspicious processes spawned by CompatTelRunner.exe with -cv* argument, indicating a possible TelemetryController task hijack.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1053.005
      - T1574
    data_sources:
      - process_creation
      - windows
  - title: TelemetryController Scheduled Task Modification
    description: Detects modification of the TelemetryController scheduled task to execute a different binary.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The Microsoft Compatibility Appraiser is a component of Windows telemetry that uses scheduled tasks to assess system compatibility. An attacker can hijack this scheduled task, named TelemetryController, to execute malicious code with elevated, system-level privileges. This grants the attacker persistence on the system, as the hijacked task will execute the malicious code each time it is triggered. The attack involves modifying the task to execute a malicious binary or script instead of its intended function. This technique allows the adversary to maintain access to the compromised system even after a reboot or other system event. This activity was observed in August 2020.

## Attack Chain

1. The attacker gains initial access to the system through an existing vulnerability or compromised credentials.
2. The attacker identifies the Microsoft Compatibility Appraiser scheduled task ("CompatTelRunner.exe") as a persistence target.
3. The attacker modifies the scheduled task's properties to execute a malicious payload (e.g., a reverse shell or custom malware) when the task is triggered. This may involve changing the program executed or adding command-line arguments.
4. The attacker ensures the modified task runs with system-level privileges, typically the default setting for this task.
5. The legitimate CompatTelRunner.exe process triggers the scheduled task, which now executes the attacker's malicious payload. The parent process remains CompatTelRunner.exe.
6. The malicious payload executes with elevated privileges, allowing the attacker to perform actions that require system-level access.
7. The attacker establishes a persistent connection to the compromised system, enabling remote access and control.
8. The attacker performs further actions on the compromised system, such as data exfiltration, lateral movement, or deploying additional malware.

## Impact

A successful hijack of the TelemetryController scheduled task grants the attacker persistent system-level access to the compromised system. This allows them to perform a wide range of malicious activities, including installing malware, stealing sensitive data, and compromising other systems on the network. The hijacked task executes with the SYSTEM account, granting the attacker the highest level of privileges on the system. This can lead to complete system compromise and significant damage to the organization.

## Recommendation

*   Monitor process creation events for processes with a parent process of `CompatTelRunner.exe` and command-line arguments containing `-cv*`, while excluding known legitimate processes such as `conhost.exe`, `DeviceCensus.exe`, `CompatTelRunner.exe`, `DismHost.exe`, `rundll32.exe`, and `powershell.exe`. Deploy the provided Sigma rule to your SIEM and tune for your environment.
*   Regularly review and audit scheduled tasks to identify any unauthorized modifications or additions.
*   Implement endpoint detection and response (EDR) solutions to detect and prevent malicious activity on endpoints.
*   Monitor Windows Security Event Logs and Sysmon logs for suspicious process creations and task modifications.
*   Refer to the investigation guide in the source for triage steps and remediation.
