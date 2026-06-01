---
title: Azure Run Command Script Child Process
slug: 2026-06-azure-run-command-script-child-process
description: This rule identifies suspicious process start events where the parent process matches Azure Virtual Machine Run Command execution patterns on Windows (PowerShell with `-ExecutionPolicy Unrestricted` and `script?.ps1`) or Linux (waagent running `script.sh` under `/var/lib/waagent/run-command/`), exposing on-guest payloads.
date: "2026-06-01T13:48:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - endpoint
  - azure
  - execution
  - azure-run-command
vendors:
  - Microsoft
products:
  - Azure Virtual Machines
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
references:
  - https://docs.microsoft.com/en-us/azure/virtual-machines/run-command
  - https://hackingthe.cloud/azure/run-command-abuse/
rules:
  - title: Azure Run Command Script Child Process - Windows
    description: Detects child processes spawned by PowerShell when used with Azure Run Command and an unrestricted execution policy on Windows.
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
  - title: Azure Run Command Script Child Process - Linux
    description: Detects child processes spawned by bash/sh/dash etc. when used with Azure Run Command on Linux.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1651
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Azure VM Run Command executes scripts on guest machines without requiring interactive RDP or SSH sessions. This feature is often used for legitimate administrative tasks, but can be abused to execute malicious payloads directly on the VM. On Windows, the Run Command typically initiates PowerShell with the `-ExecutionPolicy Unrestricted` parameter and executes a `script?.ps1` file. On Linux, the Azure Linux Agent (waagent) executes downloaded scripts, typically named `script.sh`, located under the `/var/lib/waagent/run-command/` directory. Monitoring child processes initiated by these Run Command patterns is crucial because it exposes the actual on-guest payload that might not be fully visible in cloud activity logs. This behavior allows defenders to identify potentially malicious scripts being executed within Azure VMs.

## Attack Chain

1. An attacker gains access to an Azure account or VM with sufficient privileges.
2. The attacker leverages Azure Run Command to execute a script on a target VM.
3. On Windows, the Run Command initiates a PowerShell process with `-ExecutionPolicy Unrestricted -File script?.ps1`.
4. This PowerShell script executes a malicious payload, such as downloading and running an executable.
5. On Linux, the Run Command causes waagent to download and execute `/var/lib/waagent/run-command/download/*/script.sh` via `bash`.
6. The shell script performs malicious actions, such as installing backdoors or exfiltrating data.
7. The malicious payload establishes persistence on the VM.
8. The attacker uses the compromised VM to move laterally within the network or achieve other objectives.

## Impact

Successful exploitation via Azure Run Command can lead to unauthorized code execution within Azure Virtual Machines. This can result in data theft, installation of malware, or the compromise of sensitive systems. While the exact number of affected organizations is unknown, this technique poses a significant risk to any organization utilizing Azure VMs without proper monitoring and access controls. The lack of detailed logging in cloud activity logs makes detection challenging, increasing the potential for undetected breaches.

## Recommendation

*   Deploy the Sigma rule "Azure Run Command Script Child Process - Windows" to detect child processes of PowerShell executing scripts with unrestricted execution policy (related to `process.parent.command_line` and `process.name`).
*   Deploy the Sigma rule "Azure Run Command Script Child Process - Linux" to detect child processes of shell interpreters executing scripts in the waagent run-command directory (related to `process.parent.args` and `process.parent.name`).
*   Correlate process creation events with Azure activity logs for `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION` events when available, as suggested in the rule's note section.
*   Implement strict Azure RBAC policies to limit which users and service principals can execute Run Command actions.
*   Regularly review and audit Azure activity logs for suspicious Run Command usage patterns.
