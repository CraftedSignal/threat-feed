---
title: Windows Eventlog Cleared Via Wevtutil
slug: 2024-01-windows-eventlog-cleared-wevtutil
description: Adversaries may clear Windows event logs using `wevtutil.exe` to remove evidence of their activity and hinder forensic investigations.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - event-logs
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.001
    technique_name: 'Indicator Removal on Host: Clear Windows Event Logs'
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.001/T1070.001.md
rules:
  - title: Windows Eventlog Cleared Via Wevtutil Execution
    description: Detects the execution of wevtutil.exe with the clear-log parameter to clear event logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
  - title: Windows Eventlog Cleared Via Wevtutil Security Log
    description: Detects the clearing of the Security event log using wevtutil.exe.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to clear Windows event logs to evade detection and hinder forensic investigations. Clearing logs removes evidence of malicious activity, making it difficult to trace attacker actions and understand the scope of a compromise. This activity is often performed after other malicious actions to remove traces of those actions. The tool `wevtutil.exe`, a legitimate Windows utility, can be used to clear event logs when invoked with the `clear-log` parameter. Detecting the use of `wevtutil.exe` with this parameter can indicate an attempt to cover tracks after malicious activities. This behavior is significant because it can prevent defenders from fully understanding the attack.

## Attack Chain

1.  Initial access is gained through unspecified means (e.g., exploiting a vulnerability or through phishing).
2.  The attacker executes commands to perform reconnaissance and privilege escalation.
3.  After achieving desired privileges and completing their objectives, the attacker uses `wevtutil.exe` to clear specific event logs.
4.  The attacker executes `wevtutil.exe` with the `clear-log` parameter, specifying the log to clear (e.g., Security, Application, System). For example: `wevtutil cl Security`.
5.  The command execution is logged by endpoint detection and response (EDR) agents, capturing the process name (`wevtutil.exe`) and command-line arguments (`clear-log`).
6.  Windows Event Logs, such as the Security log, are cleared of their contents, removing entries related to the attacker's activities.
7.  Forensic investigations are hampered due to missing event log data, making it difficult to trace the attacker's actions and understand the full scope of the compromise.

## Impact

Successful clearing of event logs can significantly impede incident response efforts. By removing evidence of their actions, attackers can prolong their presence in the compromised environment and make it more difficult to identify the extent of the damage. In cases of ransomware attacks, this could delay recovery efforts and increase the overall impact. The detection is based on data that originates from Endpoint Detection and Response (EDR) agents.

## Recommendation

*   Enable process creation logging, specifically Sysmon Event ID 1 or Windows Event Log Security 4688, to capture `wevtutil.exe` executions.
*   Deploy the provided Sigma rules to your SIEM to detect the execution of `wevtutil.exe` with the `clear-log` parameter.
*   Investigate any detected instances of `wevtutil.exe` being used to clear logs, as this could indicate malicious activity.
*   Tune the Sigma rules for false positives based on legitimate administrator usage of `wevtutil.exe` in your environment.
