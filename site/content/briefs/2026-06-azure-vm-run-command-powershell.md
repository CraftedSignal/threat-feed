---
title: Azure Run Command Correlated with Process Execution
slug: 2026-06-azure-vm-run-command-powershell
description: This rule detects the abuse of Azure Virtual Machine Run Command to execute scripts remotely, correlating Azure Activity Log events with endpoint process starts, identifying instances where adversaries use Run Command to run scripts as SYSTEM or root.
date: "2026-06-01T13:48:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - endpoint
  - execution
  - azure
  - powershell
vendors:
  - Microsoft
  - Elastic
products:
  - Azure
  - Elastic Defend
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
references:
  - https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#virtual-machine-contributor
  - https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a
  - https://adsecurity.org/?p=4277
rules:
  - title: Azure Run Command - PowerShell Execution
    description: Detects PowerShell execution on Windows VMs initiated via Azure Run Command with unrestricted execution policy.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1651
    data_sources:
      - process_creation
      - windows
  - title: Azure Run Command - Linux Shell Script Execution
    description: Detects shell script execution on Linux VMs initiated via Azure Run Command.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
      - T1651
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection identifies the abuse of Azure Virtual Machine Run Command to execute scripts remotely, correlating Azure Activity Log events with endpoint process starts. Adversaries can leverage Run Command to execute scripts with SYSTEM or root privileges, while only control-plane actions are logged. Elastic Defend process telemetry reveals the on-guest payload. The rule focuses on detecting PowerShell execution with unrestricted policy and numbered script files (script?.ps1), as well as shell scripts executed from the /var/lib/waagent/run-command/download/ directory. It aims to correlate these actions with Azure Activity Logs to provide a comprehensive view of potential exploitation attempts.

## Attack Chain

1. An attacker gains access to an Azure account or VM with sufficient permissions to execute Run Commands (e.g., Virtual Machine Contributor role).
2. The attacker invokes the Azure Run Command feature, specifying a PowerShell or shell script to be executed on the target VM.
3. The Run Command service downloads the specified script to a temporary location on the VM, typically under `/var/lib/waagent/run-command/download/` for Linux VMs.
4. The script is executed on the target VM with elevated privileges (SYSTEM on Windows, root on Linux). For PowerShell, the script is executed with the `-ExecutionPolicy Unrestricted` flag.
5. If the script is PowerShell, powershell.exe spawns a child process to run the script.
6. The attacker may use the executed script to perform various malicious actions, such as installing malware, exfiltrating data, or establishing persistence.
7. Azure Activity Logs record the invocation of the Run Command, but may not capture the details of the script's execution.
8. Elastic Defend captures the process execution events on the endpoint, providing visibility into the script's activity and potential malicious behavior.

## Impact

Successful exploitation allows attackers to execute arbitrary code with elevated privileges on Azure Virtual Machines. This can lead to data theft, system compromise, or further lateral movement within the cloud environment. The lack of detailed logging in Azure Activity Logs can make it difficult to detect and investigate these attacks.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune for your environment to detect suspicious PowerShell execution patterns correlated with Azure Run Command invocation.
*   Review `user.email` and `azure.activitylogs.identity.authorization.evidence.principal_id` for who invoked Run Command as described in the rule's "Triage and Analysis" section.
*   Inspect `Esql.process_command_line_values` for script paths and arguments beyond the matched pattern as described in the rule's "Triage and Analysis" section.
*   Monitor Azure Activity Logs for `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION` events to identify potential Run Command abuse.
