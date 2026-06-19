---
title: Azure VM Managed Run Command Abuse for Execution and Persistence
slug: 2026-06-azure-vm-run-command-abuse
description: Adversaries can abuse the Azure VM Managed Run Command feature (MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE) to achieve code execution as System or root and establish persistence on Azure Virtual Machines or Virtual Machine Scale Sets by an unusual identity, potentially evading detections focused solely on action-based Run Commands.
date: "2026-06-19T15:50:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - azure
  - execution
  - persistence
  - defense-evasion
  - vm
  - iac
vendors:
  - Microsoft
products:
  - Azure Virtual Machines
  - Azure Virtual Machine Scale Sets
  - Azure Run Command
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
references:
  - https://www.netspi.com/blog/technical-blog/adversary-simulation/7-ways-to-execute-command-on-azure-virtual-machine-virtual-machine-scale-sets/
  - https://learn.microsoft.com/en-us/azure/virtual-machines/windows/run-command-managed
  - https://hackingthe.cloud/azure/run-command-abuse/
  - https://blog.pwnedlabs.io/diving-deep-into-azure-vm-attack-vectors
  - https://www.sysdig.com/blog/the-expendable-extension-name-azure-vmaccess-naming-chaos-password-resets-and-a-detection-gap
rules:
  - title: Azure VM Managed Run Command Write Operation
    description: Detects the creation or update of an Azure VM Managed Run Command resource, which can be abused for code execution and persistence. This rule targets the MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE operation, emphasizing that any such action, especially by an unusual principal, warrants investigation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - persistence
    techniques:
      - T1651
    data_sources:
      - cloud
      - azure
  - title: Azure VM Extension Write Operation
    description: Detects the creation or update of an Azure VM Extension, a common method for achieving code execution and persistence on Azure virtual machines. This operation, similar to managed run commands, allows for the execution of scripts and is often abused by attackers.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.006
      - T1543.003
      - T1651
    data_sources:
      - cloud
      - azure
rules_count: 2
---

Adversaries are known to leverage legitimate cloud platform functionalities for malicious purposes, and the Azure VM Managed Run Command is one such target. This feature allows for the creation or update of a persistent resource on an Azure Virtual Machine or Virtual Machine Scale Set, which executes a supplied script with high privileges (System on Windows, root on Linux). Unlike the ephemeral "runCommand/action," the managed Run Command, identified by operations such as "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE," leaves a durable object, making it suitable for establishing persistence. This technique allows attackers to evade detection mechanisms that primarily monitor transient command executions. Detection focuses on identifying instances where an identity that has not previously performed this operation initiates a managed run command, signaling unusual or unauthorized activity.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to an Azure environment, typically through compromised credentials for an Azure Active Directory principal with sufficient permissions (e.g., Virtual Machine Contributor, Owner role on a resource group or subscription).
2.  **Reconnaissance:** The attacker identifies target Azure Virtual Machines or Virtual Machine Scale Sets that can be accessed and abused for execution and persistence.
3.  **Defense Evasion:** To avoid detection by security tools monitoring common execution methods, the attacker opts to use the less commonly scrutinized Managed Run Command (`runcommands/write`) instead of the action-based `runCommand/action`.
4.  **Execution via Managed Run Command:** The compromised principal creates or updates a Managed Run Command resource on the target VM/VMSS, embedding a malicious script. This action executes the script as System (Windows) or root (Linux) upon creation/update.
5.  **Persistence Establishment:** The Managed Run Command resource itself serves as a persistent backdoor, allowing the attacker to re-execute the script or maintain a foothold.
6.  **Command and Control (C2):** The executed script establishes a C2 channel, allowing the attacker to remotely control the compromised VM.
7.  **Lateral Movement / Data Exfiltration:** With C2 established and high privileges, the attacker proceeds with further objectives, such as lateral movement within the Azure environment or exfiltration of sensitive data.
8.  **Impact:** The attacker maintains control and can perform arbitrary actions on the compromised virtual machine.

## Impact

Successful exploitation of this technique grants adversaries System (Windows) or root (Linux) level code execution on targeted Azure Virtual Machines and Virtual Machine Scale Sets. This leads to persistent access to the compromised resources, allowing attackers to establish command and control, deploy additional malware, steal sensitive data, pivot to other resources within the Azure subscription, or disrupt operations. The persistent nature of the managed run command means that even after a potential reboot, the attacker's script could re-execute, maintaining the breach. While specific victim counts are not available for this technique, it poses a significant risk to any organization utilizing Azure IaaS with insufficient logging or monitoring.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM solution to detect suspicious Azure Managed Run Command operations.
*   Configure Azure Activity Logs to be ingested into your SIEM for correlation and analysis, specifically for the `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE` operation.
*   Baseline expected service principals, managed identities, and administrator users that legitimately create or update Azure VM Managed Run Commands and exclude them from alerting to reduce false positives.
*   Investigate `azure.activitylogs.identity.authorization.evidence.principal_id` for any unusual principal executing managed run commands.
*   Review the RBAC roles assigned to principals triggering these alerts, focusing on least privilege.
*   Correlate alerts with `source.ip` to identify if the activity originates from unusual or untrusted IP addresses.
