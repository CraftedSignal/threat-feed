---
title: Abuse of PowerShell Cmdlets for Scheduled Task Manipulation
slug: 2026-09-powershell-scheduled-tasks
description: Adversaries leverage native Windows PowerShell cmdlets to register, configure, and execute unauthorized scheduled tasks for persistence and lateral movement.
date: "2026-09-03T13:37:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - privilege-escalation
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code
    confidence_band: high
rules:
  - title: Detect PowerShell Scheduled Task Creation
    description: Detects the use of PowerShell cmdlets or CIM methods to create or register scheduled tasks for potential persistence
    platform: sigma
    severity: medium
    tactics:
      - execution
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
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints
      owner: IT Operations
      due: 48h
      evidence: Required telemetry for rule activation
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Sigma rule provided in brief
  hunt_leads:
    - lead: Search for instances of Register-ScheduledTask or Invoke-CimMethod pointing to unauthorized executables or scripts
      technique_id: T1053.005
      data_needed:
        - Event ID 4104
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Commonly abused PowerShell cmdlets for task registration
  mitigation_plan:
    - priority: short_term
      action: Restrict the ability of non-administrative users to create or modify scheduled tasks via group policy
      owner: IT Operations
      addresses: T1053.005
      evidence: Technique relies on task scheduler permissions
---

Threat actors frequently abuse the Windows Task Scheduler to establish persistence, achieve privilege escalation, or ensure recurring execution of malicious payloads. By utilizing native PowerShell cmdlets such as Register-ScheduledTask or through direct WMI/CIM method calls to the TaskScheduler namespace, attackers can create or modify system tasks without requiring external binaries or manual interaction with the GUI. This technique is particularly effective in environments where PowerShell is trusted and Script Block Logging is not actively monitored, allowing attackers to blend in with legitimate administrative automation. Defenders must focus on the invocation of specific task-related cmdlets to differentiate malicious persistence mechanisms from benign system management scripts.

## Attack Chain

1. The attacker gains initial access to the target host via phishing or exploit.
2. The attacker identifies the need for recurring code execution for persistence.
3. The attacker executes a PowerShell command using New-ScheduledTaskAction and New-ScheduledTaskTrigger to define the payload and timing.
4. The attacker defines a security context for the task using New-ScheduledTaskPrincipal.
5. The attacker finalizes the configuration using New-ScheduledTaskSettingsSet.
6. The attacker uses Register-ScheduledTask or Invoke-CimMethod to commit the task to the Windows Task Scheduler.
7. The scheduled task executes the malicious payload upon the next trigger event (e.g., system boot, user login).

## Impact

Successful abuse of the Windows Task Scheduler allows attackers to maintain long-term access to compromised systems, even after system reboots. This capability is commonly used by various threat actors to deploy ransomware, exfiltrate data, or deploy additional C2 implants across enterprise networks.

## Recommendation

Deploy the provided Sigma rule to identify unauthorized task creation. Ensure PowerShell Script Block Logging (Event ID 4104) is enabled across the endpoint estate to capture the specific cmdlets used during task registration. Audit all existing scheduled tasks for unexpected actions or suspicious command-line arguments.
