---
title: Detection of PowerShell Remote Session Establishment
slug: 2026-09-powershell-remote-sessions
description: Adversaries utilize the New-PSSession cmdlet to establish remote PowerShell sessions for lateral movement and command execution within Windows environments.
date: "2026-09-03T13:41:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - lateral-movement
  - powershell
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries may abuse PowerShell commands and scripts for execution.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_remote_session_creation.yml
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession
rules:
  - title: Detect PowerShell Remote Session Creation
    description: Detects the use of the New-PSSession cmdlet targeting a remote computer, which may indicate lateral movement
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into PowerShell script content
  hunt_leads:
    - lead: Search for high volumes of New-PSSession commands originating from workstations rather than jump servers
      technique_id: T1059.001
      data_needed:
        - Event ID 4104 logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: New-PSSession is a common indicator of lateral movement
---

PowerShell is a standard administrative tool that is frequently abused by threat actors to perform lateral movement and remote code execution across enterprise networks. By using the New-PSSession cmdlet, attackers can establish persistent connections to remote hosts, allowing them to execute commands, stage additional malware, or exfiltrate data from compromised assets. This technique is often seen in the context of fileless attacks where malicious scripts are executed in memory. Monitoring for the creation of these sessions is critical for identifying unauthorized lateral movement and preventing the escalation of privileges within a domain environment. Defenders should focus on capturing PowerShell Script Block logs to gain visibility into the command structure and parameters used during these sessions.

## Impact

Successful abuse of remote PowerShell sessions allows attackers to move laterally through an environment without the need for additional specialized tooling. This can lead to the compromise of sensitive data, domain-wide privilege escalation, and persistent access for threat actors. If left undetected, attackers can maintain control over multiple endpoints while avoiding traditional file-based detection mechanisms.

## Recommendation

Prioritized actions for detection and prevention:
- Enable PowerShell Script Block Logging (Event ID 4104) across the environment to capture full command executions.
- Deploy the Sigma rule below to identify the use of New-PSSession with remote computer targets.
- Baseline legitimate administrative activity to reduce noise, specifically excluding known automation service accounts or management servers.
- Implement restrictive PowerShell constrained language mode where administrative requirements permit.
