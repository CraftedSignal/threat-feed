---
title: Scheduled Task Execution of Encoded PowerShell Registry Payloads
slug: 2026-09-schtasks-reg-encoded
description: Adversaries utilize the Windows Task Scheduler to execute obfuscated PowerShell commands retrieved from Registry keys to maintain persistence and execute payloads.
date: "2026-09-03T12:44:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - execution
  - fileless
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Adversaries utilize the Windows Task Scheduler to execute obfuscated PowerShell commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: By leveraging the Get-ItemProperty cmdlet combined with System.Convert::FromBase64String, the attacker decodes and executes the payload directly into memory using IEX.
    confidence_band: high
rules:
  - title: Detect Scheduled Task Executing Encoded Registry Payload
    description: Detects the creation of a scheduled task that executes a base64 encoded PowerShell payload retrieved from a registry key.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
      - privilege-escalation
    techniques:
      - T1053.005
      - T1059.001
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
    - action: Deploy Sigma detection rule to monitor schtasks command lines.
      owner: Detection Engineering
      due: 24h
      evidence: Source rule provided by SigmaHQ.
  hunt_leads:
    - lead: Search for existing scheduled tasks that contain 'FromBase64String' or 'Get-ItemProperty' in their action field.
      technique_id: T1053.005
      data_needed:
        - Scheduled task configuration exports
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This technique is commonly used for persistent stealth access.
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict registry and filesystem permissions.
      owner: IT Operations
      addresses: Prevention of payload storage.
      evidence: Registry-based payload storage is a prerequisite for this technique.
---

This threat involves the use of legitimate Windows administrative tools, specifically 'schtasks.exe', to establish persistence by triggering a scheduled task. The scheduled task is configured to execute a PowerShell command that retrieves an obfuscated payload stored within a specific Windows Registry key. By leveraging the 'Get-ItemProperty' cmdlet combined with 'System.Convert::FromBase64String', the attacker decodes and executes the payload directly into memory using 'IEX' (Invoke-Expression). This technique allows for fileless execution, bypassing traditional file-based signature detection. This methodology has been observed in campaigns leading to full domain compromise, where attackers seek to maintain long-term access while minimizing disk footprint. Defenders should focus on monitoring task creation events that reference registry interaction via PowerShell.

## Attack Chain

1. Attacker writes an encoded malicious script to a custom registry key (e.g., HKCU:\SOFTWARE\AppDataName) using reg.exe or PowerShell.
2. Attacker executes 'schtasks.exe /Create' to establish a new persistence task.
3. The task is configured with a trigger frequency (e.g., /SC MINUTE /MO 30).
4. The task command-line argument contains a 'powershell -Command' string invoking 'Get-ItemProperty' to fetch the registry data.
5. The retrieved string is passed to 'FromBase64String' for decoding.
6. The decoded payload is piped into 'IEX' for execution within the PowerShell process context.
7. The malicious code runs in the background, typically with the privileges of the user account under which the task is scheduled.

## Impact

This technique facilitates stealthy persistence, allowing attackers to maintain access across system reboots. If successful, it often serves as a precursor to credential harvesting, lateral movement, or ransomware deployment, potentially leading to full domain-wide compromise as observed in previous real-world incidents.

## Recommendation

* Deploy the Sigma rule below to detect 'schtasks.exe' command-line patterns involving PowerShell registry retrieval and decoding.
* Monitor Windows Event ID 4698 (A scheduled task was created) to identify tasks configured with suspicious command-line arguments.
* Restrict write access to sensitive registry hives (HKLM) to prevent attackers from storing payloads in common configuration locations.
