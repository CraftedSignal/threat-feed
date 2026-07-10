---
title: Windows Persistence via Scheduled Job Creation
slug: 2024-01-scheduled-job-persistence
description: Adversaries can abuse the Windows Task Scheduler to establish persistence by creating malicious scheduled jobs, which are detected by monitoring for the creation of '.job' files in the 'Windows\Tasks' directory while excluding known legitimate software.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - windows
  - scheduled-task
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_local_scheduled_job_creation.toml
  - https://attack.mitre.org/techniques/T1053/
  - https://attack.mitre.org/techniques/T1053/005/
  - https://attack.mitre.org/tactics/TA0003/
rules:
  - title: Persistence via Scheduled Job Creation
    description: Detects the creation of scheduled job files (.job) in the Windows Tasks directory, excluding known false positives.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - file_event
      - windows
  - title: Detect Scheduled Task Creation via Schtasks.exe
    description: Detects the creation of scheduled tasks using the schtasks.exe command-line utility, a common method for establishing persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can establish persistence on Windows systems by creating or modifying scheduled tasks. This involves creating '.job' files within the `C:\\Windows\\Tasks` directory. Legitimate software installations and updates can also create scheduled tasks, leading to potential false positives. This activity is detected by monitoring file creation events with a focus on specific file paths and extensions associated with scheduled jobs. The rule excludes known legitimate processes such as CCleaner and ManageEngine to minimize false positives. Successful exploitation allows attackers to maintain long-term access to compromised systems, enabling them to execute malicious code at specified intervals without user interaction. This activity has been observed across various Windows environments and can lead to significant security breaches.

## Attack Chain

1.  The attacker gains initial access to the target system through various means, such as exploiting a vulnerability or using stolen credentials.
2.  The attacker uses a command-line interface (e.g., `cmd.exe`, `powershell.exe`) to interact with the Task Scheduler.
3.  The attacker crafts a malicious `.job` file in the `C:\\Windows\\Tasks\\` directory using tools like `schtasks.exe` or by directly writing the file. The file extension ".job" is a key identifier.
4.  The scheduled task is configured to execute a malicious script or program (e.g., PowerShell script, executable file) at a specific time or event.
5.  The Task Scheduler service (`taskeng.exe`) executes the scheduled task according to the defined schedule.
6.  The malicious script or program performs actions such as downloading malware, executing commands, or establishing a reverse shell.
7.  The attacker maintains persistent access to the system as the scheduled task continues to execute at the specified intervals.
8.  The attacker can perform further malicious activities, such as data exfiltration, lateral movement, or deploying ransomware.

## Impact

Successful exploitation leads to persistent access on the compromised system, enabling the attacker to execute arbitrary code at scheduled intervals without user interaction. This can result in data theft, system compromise, or further propagation of malware within the network. The impact can range from minor disruptions to significant financial losses and reputational damage, depending on the attacker's objectives and the sensitivity of the compromised data. The creation of persistent scheduled tasks is a common tactic used in various ransomware and data theft campaigns, affecting organizations across different sectors.

## Recommendation

*   Enable Sysmon file creation logging to monitor `.job` file creation in `C:\\Windows\\Tasks\\` (reference: `logs-windows.sysmon_operational-*`).
*   Deploy the Sigma rule "Persistence via Scheduled Job Creation" to your SIEM and tune for your environment (reference: rule section).
*   Review and update exclusion lists for legitimate scheduled jobs regularly to minimize false positives (reference: false positives analysis in content section).
*   Implement enhanced monitoring and alerting for scheduled job creation activities across the network to detect similar threats in the future, leveraging the specific query fields used in the detection rule (reference: query in content section).
