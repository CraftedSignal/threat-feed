---
title: Detection of Remote Scheduled Task Initiation via Schtasks
slug: 2026-10-scheduled-task-remote
description: This brief describes the detection of adversaries abusing 'schtasks.exe' for lateral movement and remote code execution by triggering scheduled tasks on remote Windows endpoints.
date: "2026-10-12T17:58:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - execution
  - living-off-the-land
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Adversaries often abuse Task Scheduler for lateral movement and remote code execution.
    confidence_band: high
rules:
  - title: Detect Remote Scheduled Task Initiation via Schtasks
    description: Detects the use of 'schtasks.exe' with the /S and /run flags to trigger a scheduled task on a remote endpoint, often used for lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
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
    - action: Deploy the provided Sigma rule to detect remote schtasks activity.
      owner: Detection Engineering
      due: 48h
      evidence: Source document identifies this as a high-value TTP for detection.
  hunt_leads:
    - lead: Search for anomalous schtasks.exe command lines in existing process logs.
      technique_id: T1053.005
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Technique is frequently used by known ransomware groups.
  mitigation_plan:
    - priority: short_term
      action: Restrict the ability of standard users to execute remote commands via schtasks.
      owner: IT Operations
      addresses: T1053.005
      evidence: Restricting administrative execution is a standard hardening practice.
---

Adversaries frequently abuse the Windows Task Scheduler as a living-off-the-land technique to facilitate lateral movement and achieve remote code execution within a compromised network. By leveraging the built-in 'schtasks.exe' utility, threat actors can trigger existing scheduled tasks on remote systems, often bypassing traditional perimeter defenses. This activity is a hallmark of post-exploitation operations, including those attributed to ransomware groups and state-sponsored actors who prioritize stealthy, built-in system administration tools to maintain access and execute malicious payloads across an enterprise environment. Detection engineering teams must focus on monitoring process execution telemetry for command lines that indicate remote task interaction to identify and contain such movement early in the attack lifecycle.

## Attack Chain

1. Attacker gains initial access to a workstation or server via phishing, exploit, or credential theft.
2. Attacker performs internal reconnaissance to identify high-value targets or domain-joined workstations.
3. Attacker uses compromised credentials to authenticate to a remote system over SMB or WinRM.
4. Attacker identifies a persistent scheduled task on the remote system to abuse or creates a new one.
5. Attacker executes 'schtasks.exe /S &lt;remote_host> /run /TN &lt;task_name>' to invoke the task remotely.
6. The remote host executes the command defined in the task, resulting in remote code execution (RCE).
7. Attacker leverages this RCE to deploy secondary payloads, exfiltrate data, or move laterally to further systems.

## Impact

Successful abuse of remote scheduled tasks allows an attacker to execute arbitrary code with the privileges associated with the task. This facilitates lateral movement, privilege escalation, and persistence across the Windows domain. If left undetected, this technique can lead to full domain compromise, large-scale ransomware deployment, or long-term covert data exfiltration.

## Recommendation

* Deploy the Sigma rule provided in this brief to detect remote task initiation attempts across your Windows server and workstation fleet.
* Enable Sysmon Event ID 1 or Windows Event ID 4688 to capture comprehensive process creation command-line logs.
* Map all process execution logs to the CIM 'Processes' data model to ensure detection logic functions correctly.
* Investigate occurrences of 'schtasks.exe' connecting to remote endpoints; tune alerts to identify deviations from known administrative service accounts.
