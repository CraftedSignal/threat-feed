---
title: Windows Event Log Clearing Detected
slug: 2024-01-03-clearing-event-logs
description: This threat brief covers the detection of adversaries clearing or disabling Windows event logs, a common defense evasion tactic, using tools like wevtutil.exe and PowerShell cmdlets to remove evidence of their activities.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - windows
  - event-logs
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://www.elastic.co/security-labs/invisible-miners-unveiling-ghostengine
  - https://attack.mitre.org/techniques/T1070/
  - https://attack.mitre.org/techniques/T1070/001/
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/002/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Windows Event Log Clearing Detected
    description: Detects attempts to clear Windows event logs using wevtutil.exe command-line utility.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
  - title: PowerShell Clear-EventLog Usage
    description: Detects usage of the Clear-EventLog PowerShell cmdlet to clear event logs.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers frequently attempt to clear or disable Windows event logs to evade detection and remove forensic evidence of their malicious actions. This activity hinders incident response and makes it difficult to trace attacker activity. This threat brief focuses on detecting the use of `wevtutil.exe` and PowerShell's `Clear-EventLog` cmdlet, tools commonly employed for this purpose. The targeted activity involves manipulating event logs to conceal unauthorized access, malware deployment, or other malicious activities. This technique directly impacts an organization's ability to conduct thorough investigations and respond effectively to security incidents, increasing the dwell time of attackers within the environment.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., through compromised credentials or exploiting a vulnerability).
2.  The attacker escalates privileges to gain administrative rights required to manipulate event logs.
3.  The attacker uses `wevtutil.exe` with arguments such as `cl` or `clear-log` to clear specific event logs.
4.  Alternatively, the attacker uses PowerShell and the `Clear-EventLog` cmdlet to achieve the same result.
5.  The attacker may disable specific event logs using `wevtutil.exe` with the `/e:false` argument.
6.  The attacker removes traces of their activity from the system, making it difficult to determine the extent of the breach.
7.  The attacker attempts to disable logging entirely using auditpol or similar tools.
8.  The attacker continues lateral movement and other malicious activities, now with reduced risk of detection.

## Impact

Successful clearing of event logs can severely impair incident response efforts. Without adequate logging, security teams lose visibility into attacker activities, making it difficult to identify the scope and timeline of the attack. This can lead to prolonged dwell time, increased data exfiltration, and greater overall damage. While this activity itself does not directly cause data breaches, it significantly hinders the ability to respond effectively to breaches that are already in progress. The inability to investigate hinders effective remediation and recovery efforts.

## Recommendation

*   Deploy the Sigma rule "Windows Event Log Clearing Detected" to your SIEM to detect the use of `wevtutil.exe` and `Clear-EventLog` (see rules section).
*   Enable Sysmon process creation logging to capture command-line arguments for detection rules (see logsource in rules section).
*   Review and harden event log permissions to limit unauthorized clearing of logs.
*   Monitor PowerShell execution logs for the use of the `Clear-EventLog` cmdlet (see rules section).
*   Investigate any detected instances of event log clearing to determine the scope and impact of the activity.
*   Correlate event log clearing activity with other suspicious behaviors to identify potentially compromised systems.
