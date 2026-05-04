---
title: Schtasks Run Task On Demand
slug: 2024-01-03-schtasks-on-demand
description: Detection of on-demand execution of Windows Scheduled Tasks via the schtasks.exe command-line utility, a common technique for persistence and lateral movement.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - schtasks
  - scheduled-task
  - persistence
  - execution
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/schtasks_run_task_on_demand.yml
rules:
  - title: Schtasks Run Task On Demand
    description: Detects the execution of schtasks.exe with the run command, indicating a scheduled task being triggered on demand.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
      - privilege_escalation
    techniques:
      - T1053
    data_sources:
      - process_creation
      - windows
  - title: Schtasks TaskName Parameter Manipulation
    description: Detects attempts to bypass task name validation or obfuscate task names when using schtasks.exe
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This analytic detects the execution of Windows Scheduled Tasks on demand using the `schtasks.exe` utility. The detection focuses on identifying `schtasks.exe` being executed with the `run` command, which is often used by adversaries to force the execution of previously created scheduled tasks. This activity is significant because attackers frequently leverage scheduled tasks for persistent access, privilege escalation, or lateral movement within a compromised network. Detecting this behavior can help defenders identify and respond to malicious activity before it leads to further compromise. The technique has been associated with various threat actors and malware families including Qakbot, XMRig, and Medusa Ransomware as well as campaigns such as CISA AA22-257A and Industroyer2.

## Attack Chain

1.  An attacker gains initial access to the system through various means (e.g., exploiting a vulnerability, phishing).
2.  The attacker establishes persistence by creating a new scheduled task using `schtasks.exe`.
3.  The attacker uses `schtasks.exe` with the `run` command to trigger the malicious scheduled task on demand.
4.  The scheduled task executes a malicious payload, such as a script or executable.
5.  The payload may perform various malicious actions, such as downloading additional malware, escalating privileges, or gathering sensitive information.
6.  The attacker moves laterally to other systems on the network by creating and running scheduled tasks remotely.
7.  The attacker attempts to disable security controls or evade detection by modifying existing scheduled tasks.
8.  The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or system disruption.

## Impact

Successful exploitation can lead to persistent access, lateral movement, and privilege escalation within the compromised environment. Attackers can use this technique to maintain a foothold on the system, spread malware to other systems on the network, and ultimately achieve their objectives, such as data theft, ransomware deployment, or disruption of critical services.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect the execution of `schtasks.exe` with the `run` command, tuning it to exclude known legitimate uses.
*   Investigate any detected instances of `schtasks.exe` execution with the `run` command to determine if they are malicious.
*   Monitor process execution data for unusual or unexpected processes being launched by scheduled tasks.
*   Implement strict access controls and regularly review and audit scheduled tasks to prevent unauthorized modifications or creations.
*   Enable Sysmon process-creation logging (Event ID 1) to capture detailed information about process executions, including command-line arguments.
