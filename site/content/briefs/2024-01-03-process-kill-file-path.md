---
title: Detection of Process Termination via File Path Using WMIC
slug: 2024-01-03-process-kill-file-path
description: This analytic detects the use of `wmic.exe` with the `delete` command to terminate a process by specifying its executable path, often used to disable security tools or critical processes during the setup of malicious activities like cryptocurrency mining.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - process-termination
  - wmic
  - cryptocurrency-mining
  - endpoint
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
references:
  - https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/process_kill_base_on_file_path.yml
rules:
  - title: Detect Process Termination via WMIC File Path
    description: Detects the use of wmic.exe to terminate processes based on their file path.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Process Termination with WMIC Using Process Name
    description: Detects the use of wmic.exe to terminate processes based on their process name.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying the use of the Windows Management Instrumentation Command-line (WMIC) utility to terminate processes by referencing their file paths. Specifically, it looks for instances where `wmic.exe` is used with the `delete` command targeting an executable path. This technique is often employed by attackers to disable security software, terminate competing processes (such as other miners), or halt critical system services, as seen in cases involving cryptocurrency miners. The activity is often associated with the initial stages of setting up malicious operations on an endpoint, giving defenders an opportunity to disrupt attacks early in the kill chain. The source material was released in 2026, but the underlying technique has been used since at least 2020.

## Attack Chain

1.  An attacker gains initial access to the system, often through methods not directly covered by this detection (e.g., exploiting a vulnerability or using compromised credentials).
2.  The attacker executes `wmic.exe` with specific parameters to target a running process.
3.  The command includes the `process` argument to specify the process to be targeted, the `executablepath` argument to identify the process by its file path, and the `delete` command to terminate the process.
4.  `wmic.exe` attempts to locate the process based on the provided file path.
5.  If the process is found, `wmic.exe` sends a termination signal to the process.
6.  The targeted process is terminated.
7.  The attacker repeats this process to disable other security tools or competing processes.
8.  The attacker proceeds with their primary objective, such as deploying and executing a cryptocurrency miner or establishing persistence.

## Impact

Successful execution of this technique can lead to the disabling of security software, allowing malware to operate unimpeded. It can also result in the termination of critical system processes, leading to system instability or data loss. Observed cases include the deployment of XMRig cryptocurrency miners following the termination of security tools. If left unchecked, this activity can significantly increase the attacker's foothold within the compromised environment, facilitating further malicious actions.

## Recommendation

*   Deploy the Sigma rule `Detect Process Termination via WMIC File Path` to your SIEM and tune it for your environment to identify malicious process termination attempts.
*   Enable Sysmon process creation logging (Event ID 1) and Windows Event Log Security (4688) to provide the necessary data for the Sigma rules.
*   Investigate any identified instances of `wmic.exe` being used with the `delete` command, especially when targeting executable paths of known security products or critical system processes.
*   Implement the `process_kill_base_on_file_path_filter` macro referenced in the search query to reduce noise.
