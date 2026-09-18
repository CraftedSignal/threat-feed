---
title: Monitoring Azure Run Command for Unauthorized Execution
slug: 2026-09-azure-run-command-abuse
description: This brief outlines detection strategies for unauthorized guest execution via the Azure Virtual Machine Run Command feature, which attackers may abuse to run arbitrary scripts without interactive access.
date: "2026-09-18T19:14:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - cloud
  - execution
  - detection-engineering
vendors:
  - Microsoft
products:
  - Azure Virtual Machine
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rule identifies process start events whose parent matches Azure Virtual Machine Run Command execution patterns.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
    evidence: Run Command feature allows remote code execution on guest VMs without interactive access.
    confidence_band: high
references:
  - https://docs.microsoft.com/en-us/azure/virtual-machines/run-command
  - https://hackingthe.cloud/azure/run-command-abuse/
rules:
  - title: Detect Azure Run Command Script Execution
    description: Detects potential abuse of Azure Run Command by identifying characteristic PowerShell or shell execution patterns on guest VMs
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1059.004
      - T1651
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to SIEM and monitor for hits
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for processes spawned by shell interpreters with paths matching /var/lib/waagent/run-command/
      technique_id: T1651
      data_needed:
        - Process creation events
      priority: medium
      confidence: medium
      disposition: hunt_now
  mitigation_plan:
    - priority: short_term
      action: Audit Azure RBAC for VirtualMachineRunCommand permissions
      owner: Cloud Security
      addresses: Unauthorized access to guest management
---

The Azure Virtual Machine Run Command feature enables administrators to execute scripts on virtual machine guests remotely, bypassing the need for interactive RDP or SSH sessions. While this is a legitimate management capability, it represents a significant risk if hijacked by threat actors who have compromised Azure RBAC permissions. On Windows guests, Run Command typically spawns PowerShell processes with specific command-line arguments like `-ExecutionPolicy Unrestricted` and a `script?.ps1` file. On Linux, the Azure Linux Agent (waagent) invokes shell scripts stored in "/var/lib/waagent/run-command/download/". Because cloud activity logs confirm the administrative request but do not always detail the on-guest payload, defenders must rely on endpoint process lineage to gain visibility into the actual malicious behavior initiated by these commands.

## Impact

Successful abuse of this feature allows attackers to achieve persistent remote code execution on guest virtual machines. This can lead to total system compromise, exfiltration of sensitive data residing on the VM, or lateral movement within the cloud environment. Given that these actions originate from the Azure control plane, they are often difficult to detect without integrated cloud and endpoint telemetry.

## Recommendation

- Deploy process-creation detection rules targeting the Azure Run Command patterns identified in this brief to your EDR or SIEM platform.
- Correlate guest-level process start events with Azure Activity Logs (look for operation name `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION`) to differentiate between legitimate administrative tasks and potential attacker activity.
- Audit and restrict Azure RBAC permissions for the `VirtualMachineRunCommand` role to ensure only necessary personnel and service principals have access.
- Baseline known-good automation scripts, deployment windows, and service account behaviors to reduce false positives in the provided detection logic.
