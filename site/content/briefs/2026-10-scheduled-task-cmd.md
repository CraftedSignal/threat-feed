---
title: Detection of Scheduled Task Manipulation via Command Shells
slug: 2026-10-scheduled-task-cmd
description: Adversaries frequently use schtasks.exe via command interpreters to establish persistence or execute malicious payloads; this detection monitors for abnormal task creation or deletion originating from non-system processes.
date: "2026-10-12T17:58:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - living-off-the-land
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Adversaries frequently leverage scheduled tasks to maintain persistence, escalate privileges, or evade detection.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Adversaries frequently leverage scheduled tasks to maintain persistence, escalate privileges, or evade detection.
    confidence_band: high
rules:
  - title: Detect Suspicious Scheduled Task Creation or Deletion via CMD
    description: Detects the creation or deletion of scheduled tasks via schtasks.exe when spawned by cmd.exe, wscript.exe, or cscript.exe, excluding activity from standard system paths.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule for detection of schtasks.exe via cmd.exe.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for detecting T1053.005 activity.
  hunt_leads:
    - lead: Search for non-system processes launching schtasks.exe with create or delete arguments.
      technique_id: T1053.005
      data_needed:
        - Process creation logs with command line information
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: The detection logic focuses on suspicious parent processes spawning schtasks.exe.
  mitigation_plan:
    - priority: short_term
      action: Restrict command shell access and scheduled task creation rights for non-administrative users.
      owner: IT Operations
      addresses: T1053.005
      evidence: Scheduled task manipulation is a known persistence vector.
---

This detection focuses on identifying suspicious manipulation of Windows Scheduled Tasks, a common technique used by threat actors to maintain persistence, escalate privileges, or execute malicious code. Adversaries often invoke 'schtasks.exe' via command-line interpreters such as 'cmd.exe', 'wscript.exe', or 'cscript.exe' to automate the execution of secondary payloads. By filtering out tasks initiated from trusted system directories like 'C:\Windows\System32' and 'C:\Program Files', as well as those initiated by service accounts, this analytic isolates anomalous activity that deviates from standard administrative workflows. This behavior is associated with numerous malware families and living-off-the-land techniques documented in security research, including Qakbot and various ransomware variants. Defenders should prioritize investigating task modifications that originate from user-context command shells, as these are strong indicators of potential system compromise and unauthorized code execution.

## Attack Chain

1. An adversary gains initial access to a Windows endpoint.
2. The attacker drops a malicious binary or script into a non-standard directory (e.g., %TEMP% or %APPDATA%).
3. The attacker opens a command shell (e.g., cmd.exe) or executes a script (wscript.exe).
4. The adversary runs 'schtasks.exe' to create a new task or modify an existing one.
5. The 'schtasks.exe' process is spawned as a child process of the initial command shell.
6. The new scheduled task is configured to execute the dropped malicious file at a specific interval or trigger.
7. The scheduled task executes, achieving persistence and potential privilege escalation.

## Impact

Successful abuse of scheduled tasks allows attackers to maintain long-term access to compromised systems even after a reboot. This technique has been observed in various large-scale campaigns, enabling attackers to deploy ransomware, exfiltrate sensitive data, or install secondary backdoors, leading to full domain compromise and significant operational disruption within targeted sectors.

## Recommendation

* Deploy the Sigma rule below to detect abnormal invocation of 'schtasks.exe'.
* Enable Sysmon Event ID 1 (Process Creation) across all Windows endpoints to capture full command-line arguments, including parent process information.
* Integrate process-level telemetry into your SIEM and map events to the Endpoint data model to ensure visibility into parent-child process relationships.
* Establish a baseline of legitimate scheduled task management in your environment to identify and tune out authorized administrative activity.
