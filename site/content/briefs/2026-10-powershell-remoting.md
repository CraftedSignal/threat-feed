---
title: Detection of PowerShell Remoting Enablement
slug: 2026-10-powershell-remoting
description: Detection of the Enable-PSRemoting cmdlet usage via PowerShell Script Block logging, which attackers often employ to establish remote access and enable lateral movement within a compromised environment.
date: "2026-10-12T17:54:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - lateral-movement
  - powershell
  - endpoint
vendors:
  - Microsoft
products:
  - PowerShell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The following analytic detects the use of the Enable-PSRemoting cmdlet, which allows PowerShell remoting on a local or remote computer.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: If confirmed malicious, this activity could allow an attacker to take control of the system remotely, execute commands, and potentially pivot to other systems within the network.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-7.3
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1021.006/T1021.006.yaml
rules:
  - title: Detect Enable-PSRemoting Execution
    description: Detects the use of the Enable-PSRemoting cmdlet, which may indicate an attacker enabling remote command execution capabilities on a system.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1021.006
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all production hosts.
      owner: IT Operations
      due: 72h
      evidence: Source requirement for implementing the analytic.
  hunt_leads:
    - lead: Search historical logs for occurrences of Enable-PSRemoting in the last 30 days.
      technique_id: T1021.006
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The analytic can indicate an attacker enabling remote command execution capabilities on a compromised system.
---

This threat brief focuses on the detection of the `Enable-PSRemoting` PowerShell cmdlet. While this command is a standard utility used by system administrators to configure a computer to receive remote PowerShell commands, its use in an unauthorized context is a significant indicator of attacker activity. Threat actors often execute this command after gaining initial access to a workstation or server to facilitate persistent remote management, arbitrary command execution, and lateral movement to other systems within the network. Because this activity generates specific telemetry through PowerShell Script Block Logging (EventCode 4104), detection engineers can identify potential staging activity. Defenders must balance this detection against standard administrative workflows to minimize false positives while ensuring visibility into potential unauthorized configuration changes.

## Impact

Successful exploitation of this technique provides an attacker with a robust channel for remote management. By enabling PowerShell remoting, an attacker can bypass traditional security controls that might otherwise limit interactive access, facilitating the deployment of additional tools, exfiltration of data, and further infiltration into the target network. The impact involves potential compromise of multiple hosts and the escalation of access from an initial endpoint to deeper segments of the infrastructure.

## Recommendation

- Enable Microsoft-Windows-PowerShell/Operational (Event ID 4104) logging on all endpoint systems to capture ScriptBlockText.
- Deploy the provided Sigma rule to detect the execution of `Enable-PSRemoting`.
- Establish a baseline of administrative activity within the environment to create allowlists for legitimate IT and DevOps service accounts that require remote management capabilities.
- Investigate any occurrences of `Enable-PSRemoting` that deviate from established maintenance windows or authorized administrative behavior.
