---
title: Detection of Level RMM Watchdog Task Creation
slug: 2024-01-level-watchdog-task
description: The creation of the 'Level Watchdog' task, indicative of the Level remote management tool installation, is detected, highlighting the potential abuse of legitimate RMM tools for persistence and execution by threat actors on Windows systems.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - rmm
  - remote-access
  - persistence
vendors:
  - Level.io
  - Splunk
products:
  - Level remote management tool
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_level_rmm_watchdog_task_created.yml
rules:
  - title: Detect Level RMM Watchdog Task Creation
    description: Detects the creation of the Level RMM watchdog task, indicating potential unauthorized use of remote management tools.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1053
    data_sources:
      - process_creation
      - windows
  - title: Detect Level RMM Process Execution
    description: Detects execution of the Level RMM main process.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on the detection of the 'Level Watchdog' scheduled task, a component of the Level remote management (RMM) tool. Level is a legitimate commercial tool that allows IT professionals and system administrators to remotely manage computer systems. However, threat actors may abuse RMM tools like Level to maintain persistence and execute malicious commands on compromised hosts. The creation of this specific task serves as an indicator of the presence of Level RMM on a system, which warrants further investigation due to the potential for misuse. This activity is detected via Windows Event Log ID 4698, specifically targeting task creation events for the '\Level\Level Watchdog' task. This detection aims to provide security teams with visibility into the potential misuse of RMM tools within their environment.

## Attack Chain

1.  An attacker gains initial access to a target Windows system through various means (e.g., phishing, exploiting a vulnerability, or compromised credentials).
2.  The attacker installs the Level RMM agent on the compromised system, potentially using administrative privileges.
3.  The Level RMM agent installation process creates the scheduled task named '\Level\Level Watchdog'.
4.  The 'Level Watchdog' task is configured to run periodically, ensuring the Level RMM agent remains active.
5.  The attacker uses the Level RMM agent to execute commands remotely on the compromised system.
6.  The attacker uses the RMM tool to maintain persistence and control over the compromised system.
7.  The attacker leverages the established RMM connection to perform lateral movement within the network.
8.  The ultimate objective could include data exfiltration, ransomware deployment, or further compromise of critical systems.

## Impact

Successful exploitation and misuse of RMM tools can lead to significant compromise, potentially affecting numerous systems within an organization. Attackers leveraging Level RMM could gain persistent access, enabling them to steal sensitive data, disrupt operations, deploy ransomware, or use compromised systems as a staging ground for further attacks. The scope of the impact depends on the attacker's objectives and the level of access gained through the RMM tool.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect the creation of the "Level Watchdog" task (EventID 4698, TaskName "\\Level\\Level Watchdog").
*   Investigate any systems where the "Level Watchdog" task is detected to determine if the RMM software is authorized and legitimate, as noted in the known false positives.
*   Monitor process execution and network connections originating from processes associated with Level RMM for suspicious activity.
*   Review and enforce policies regarding the use of RMM tools within the organization to prevent unauthorized installations.
