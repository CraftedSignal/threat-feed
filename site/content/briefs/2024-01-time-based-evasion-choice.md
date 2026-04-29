---
title: Windows Time-Based Evasion via Choice Exec
slug: 2024-01-time-based-evasion-choice
description: Detection of choice.exe used in batch files for time-based evasion, a technique observed in SnakeKeylogger malware, indicating potential stealthy code execution and persistence.
date: "2024-01-03T15:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - time-based-evasion
  - malware
  - persistence
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Windows
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1497
    technique_name: Virtualization/Sandbox Evasion
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.404keylogger
rules:
  - title: Detect Choice.exe Time Delay
    description: Detects the use of choice.exe with time-delay parameters, a technique used for evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1497.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Batch Script with Choice.exe Time Delay
    description: Detects batch script execution using choice.exe for time delays, indicative of potential evasion techniques.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1497.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on the detection of `choice.exe` being used within batch files as a time-delay tactic, a technique notably employed by the SnakeKeylogger malware. The analysis leverages data from Endpoint Detection and Response (EDR) agents, scrutinizing process names and command-line executions. This behavior is significant because it suggests the implementation of time-based evasion techniques designed to circumvent detection mechanisms. Successful evasion could enable attackers to execute malicious code covertly, remove incriminating files, and establish persistent access on compromised systems. The use of `choice.exe` for such purposes warrants immediate investigation by security operations center (SOC) analysts due to the potential for significant system compromise and data exfiltration.

## Attack Chain

1.  The attacker gains initial access via an unknown vector.
2.  A batch script is executed on the target system.
3.  The batch script uses `choice.exe` with the `/T` and `/N` parameters to introduce a time delay. The `/T` parameter specifies a timeout period, and the `/N` parameter suppresses the display of choices.
4.  This delay allows the malware to evade time-sensitive detection mechanisms.
5.  After the delay, the script executes further commands, potentially downloading and executing a payload.
6.  The payload executes, installing a keylogger such as SnakeKeylogger or 0bj3ctivity Stealer.
7.  The keylogger captures sensitive information such as keystrokes and clipboard data.
8.  The stolen data is exfiltrated to a remote server.

## Impact

Compromised systems can lead to data theft, intellectual property loss, and financial fraud. SnakeKeylogger and similar malware have been used to steal credentials and sensitive information from various targets. Successful exploitation could result in significant financial losses, reputational damage, and legal liabilities. The number of victims and the extent of the damage depend on the attacker's objectives and the compromised systems' value.

## Recommendation

*   Deploy the Sigma rule `Detect Choice.exe Time Delay` to your SIEM to detect the use of `choice.exe` with time-delay parameters (log source: `process_creation`).
*   Enable Sysmon process creation logging (Event ID 1) to capture the necessary process execution data for the Sigma rule.
*   Investigate any instances of `choice.exe` being used with the `/T` and `/N` parameters to determine if it is part of a malicious script.
*   Block the execution of unsigned or untrusted batch scripts to prevent the initial execution of the malicious code.
*   Monitor endpoint activity for suspicious processes and network connections originating from systems where `choice.exe` has been detected.
