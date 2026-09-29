---
title: Abuse of CrowdStrike Real Time Response for Remote Command Execution
slug: 2026-09-crowdstrike-rtr-abuse
description: Attackers with unauthorized access to a CrowdStrike management console can leverage the 'runscript' functionality to execute arbitrary PowerShell commands on remote Windows hosts.
date: "2026-09-29T10:11:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - powershell
  - edr-abuse
vendors:
  - CrowdStrike
products:
  - Falcon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The detection monitors for the execution of PowerShell scripts initiated via the CrowdStrike Real Time Response 'runscript' command.
    confidence_band: high
rules:
  - title: Detect CrowdStrike RTR Script Execution
    description: Detects PowerShell execution originating from the CrowdStrike RTR process, potentially indicating unauthorized use of the 'runscript' command.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
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
    - action: Deploy the provided Sigma rule for PowerShell process creation from dllhost.exe
      owner: Detection Engineering
      due: 48h
      evidence: Source detection logic provided by Splunk ESCU
  hunt_leads:
    - lead: Search historical logs for powershell.exe execution with dllhost.exe as the parent
      technique_id: T1059.001
      data_needed:
        - Endpoint process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: This activity is characteristic of RTR misuse
---

This threat involves the abuse of the CrowdStrike Falcon Real Time Response (RTR) feature by adversaries who have compromised a legitimate CrowdStrike management console. By utilizing the 'runscript' capability, actors can push and execute arbitrary PowerShell scripts on remote, managed Windows endpoints. This technique effectively weaponizes a trusted security tool to perform post-compromise activities, such as reconnaissance, lateral movement, or malware deployment, while masquerading as legitimate administrative maintenance. Defenders should be aware that this activity originates from 'dllhost.exe' with specific command-line parameters associated with the RTR service, making it a critical visibility gap for organizations relying on EDR telemetry without specific monitoring for management-console-initiated execution.

## Attack Chain

1. Attacker gains unauthorized credentials or session access to a target organization's CrowdStrike Falcon management console.
2. Attacker initiates an RTR session to a chosen managed Windows endpoint.
3. Attacker uploads or selects a malicious PowerShell script for execution via the 'runscript' command.
4. The CrowdStrike agent triggers the execution, resulting in 'dllhost.exe' spawning 'powershell.exe'.
5. The spawned process executes with specific command-line arguments, including '-EncodedCommand' and '-Version 5.1'.
6. Malicious code executes in the context of the CrowdStrike agent or the designated service account.
7. Attacker achieves objectives such as data exfiltration, payload deployment, or further privilege escalation.

## Impact

Successful abuse of the RTR feature allows an attacker to operate with the same privileges as the security agent, potentially leading to full host compromise, sensitive data exfiltration, or the disabling of other security controls. This technique is particularly dangerous as it originates from trusted security infrastructure, potentially bypassing standard EDR behavioral blocking.

## Recommendation

Prioritize monitoring for the execution patterns of the CrowdStrike RTR agent to detect unauthorized script execution.
- Deploy the provided Sigma rule to detect PowerShell execution originating from the RTR-specific parent process ('dllhost.exe').
- Audit and restrict administrative access to the CrowdStrike management console, enforcing multi-factor authentication for all sessions.
- Review and baseline legitimate administrative RTR scripts; filter alerts to exclude known-good maintenance activity initiated by authorized security personnel.
