---
title: Azure Compute VM Command Execution Detected
slug: 2024-01-24-azure-vm-command-execution
description: Successful execution of commands on Azure Virtual Machines, specifically the MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION operation, may indicate unauthorized activity or lateral movement attempts.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - execution
  - cloud
  - vm
vendors:
  - Microsoft
products:
  - Azure Virtual Machines
  - Azure Compute
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
references:
  - https://adsecurity.org/?p=4277
  - https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a
  - https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#virtual-machine-contributor
rules:
  - title: Azure Compute VM Command Executed
    description: Detects command execution on a virtual machine in Azure via the RunCommand action.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1651
    data_sources:
      - cloudtrail
      - azure
      - activitylog
  - title: Azure Compute VM Command Execution - PowerShell
    description: Detects PowerShell command execution on a virtual machine in Azure via the RunCommand action.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1651
    data_sources:
      - cloudtrail
      - azure
      - activitylog
rules_count: 2
---

This detection identifies command execution on Azure Virtual Machines (VMs) by monitoring Azure activity logs for the `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION` operation. While roles like Virtual Machine Contributor allow managing VMs, they do not inherently grant access. However, adversaries can leverage PowerShell to remotely execute commands on a VM as the SYSTEM user. This rule is triggered upon successful command execution and could indicate malicious activity, particularly if initiated by unexpected users or systems. The rule aims to detect unauthorized command executions, potentially revealing lateral movement or unauthorized access attempts. Originally created in August 2020, this rule was last updated on April 10, 2026.

## Attack Chain

1.  An attacker compromises an Azure account or service principal with Virtual Machine Contributor or similar permissions.
2.  The attacker authenticates to the Azure environment using the compromised credentials.
3.  The attacker identifies a target Azure Virtual Machine.
4.  The attacker utilizes the `RunCommand` feature of the Azure Compute service to execute commands on the target VM. This leverages the `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION` operation.
5.  The command is executed on the VM with SYSTEM privileges.
6.  The attacker attempts to perform reconnaissance, such as listing directory contents, user accounts, or network configurations.
7.  The attacker may attempt to move laterally by installing malware, creating new accounts, or modifying system configurations.
8.  The attacker achieves their objective, such as data exfiltration or establishing persistence within the Azure environment.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, installation of malware, lateral movement within the Azure environment, and potential compromise of other resources. While the specific number of victims and targeted sectors are not provided, the impact on affected organizations includes data breaches, system downtime, and reputational damage. The damage depends on the commands executed and the attacker's ultimate objectives.

## Recommendation

*   Deploy the Sigma rule `Azure Compute VM Command Executed` to your SIEM to detect suspicious command executions (see below).
*   Review Azure activity logs for the `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION` operation and investigate any unexpected command executions.
*   Implement least privilege access controls for Azure resources, limiting the ability to execute commands on VMs to only authorized users and service principals.
*   Monitor the roles and permissions of users and service principals with Virtual Machine Contributor roles, revoking unnecessary permissions.
*   Configure alerting on successful `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION` events to enable rapid incident response.
*   Correlate command execution events with other security logs to identify potential lateral movement or other suspicious activities.
