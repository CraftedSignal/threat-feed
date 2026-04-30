---
title: Windows EventLog Autologger Session Disabled via Registry Modification
slug: 2024-01-autologger-disable
description: Adversaries may attempt to disable Windows EventLog autologger sessions via registry modification to evade detection and prevent security monitoring of early boot activities and system events.
date: "2024-01-09T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - attack.defense-evasion
  - attack.t1562.002
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session
  - https://ptylu.github.io/content/report/report.html?report=25
  - https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_autologger_session_registry_modification.yml
rules:
  - title: Windows EventLog Autologger Session Registry Modification via Reg.exe
    description: Detects attempts to disable Windows EventLog autologger sessions via registry modification using reg.exe
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Windows EventLog Autologger Session Registry Modification via PowerShell
    description: Detects attempts to disable Windows EventLog autologger sessions via registry modification using PowerShell
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may disable Windows EventLog autologger sessions by modifying specific registry keys, thus evading detection and preventing security monitoring of early boot activities and system events. The AutoLogger event tracing session records events early in the operating system boot process, allowing applications and device drivers to capture traces before user login. Disabling these sessions can blind security monitoring tools, especially those focused on early boot activity, making it harder to detect malicious activity. This technique allows attackers to operate with less scrutiny during critical phases of system startup, potentially enabling persistence or other malicious objectives.

## Attack Chain

1.  The attacker gains initial access to the system, possibly through exploitation of a vulnerability or through stolen credentials.
2.  The attacker uses `reg.exe` or PowerShell to modify the registry.
3.  The attacker targets registry keys under `\Control\WMI\Autologger\`.
4.  The attacker modifies the `Start` value to disable specific autologger sessions like EventLog-Application or EventLog-System.
5.  Alternatively, the attacker modifies the `Enabled` value to disable specific providers of an autologger session.
6.  The attacker executes the command, changing the registry value to disable the targeted autologger session or provider.
7.  The system no longer records events for the disabled autologger session or provider.

## Impact

Disabling the Windows EventLog autologger can severely impact an organization's ability to detect and respond to threats. Security monitoring tools that rely on these logs will be unable to record early boot activities and system events, leading to a gap in visibility. This can allow attackers to establish persistence mechanisms, escalate privileges, or perform other malicious activities without being detected. The impact could range from undetected malware infections to significant data breaches, depending on the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule `Windows EventLog Autologger Session Registry Modification Via CommandLine` to your SIEM and tune for your environment to detect this behavior in your environment.
*   Monitor process creation events for `reg.exe`, `powershell.exe`, or `pwsh.exe` with command-line arguments that contain `\Control\WMI\Autologger\` and either `Start` or `Enabled` based on the Sigma rule's detections.
*   Implement Atomic Red Team simulations to validate detections and train security staff.
*   Investigate any instances of registry modifications related to Autologger sessions to determine if they are legitimate or malicious.
