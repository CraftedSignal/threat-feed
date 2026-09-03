---
title: Detection of Remote PowerShell Invoke-Command Execution
slug: 2026-09-invoke-command-remote
description: Adversaries leverage the PowerShell Invoke-Command cmdlet to perform lateral movement and execute arbitrary code on remote Windows hosts via WinRM.
date: "2026-09-03T13:40:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - powershell
  - winrm
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM).
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_command_remote.yml
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command?view=powershell-7.4
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.006/T1021.006.md
rules:
  - title: Detect Remote Invoke-Command Execution
    description: Detects the use of the Invoke-Command cmdlet with the ComputerName parameter, a common pattern for lateral movement via WinRM.
    platform: sigma
    severity: medium
    tactics:
      - lateral-movement
    techniques:
      - T1021.006
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for remote PowerShell activity.
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided by SigmaHQ.
  mitigation_plan:
    - priority: medium_term
      action: Restrict WinRM access to authorized jump servers or administrative workstations.
      owner: IT Operations
      addresses: T1021.006
      evidence: General security best practice for T1021.
---

Adversaries frequently use legitimate administrative tools, such as the PowerShell Invoke-Command cmdlet, to conduct lateral movement across enterprise networks. By leveraging Windows Remote Management (WinRM), attackers can execute scripts and commands on remote systems without the need for additional malware installation. This technique, identified as T1021.006, allows actors to maintain persistence, collect information, or deploy additional payloads using existing system accounts. Defenders should focus on capturing PowerShell Script Block Logging events to identify the misuse of remoting capabilities in environments where such activity is not expected for standard administrative operations.

## Impact

Successful abuse of Invoke-Command enables unauthorized code execution across the network, facilitating lateral movement and privilege escalation. This technique is commonly observed during the post-exploitation phase of intrusions, potentially leading to widespread data exfiltration, ransomware deployment, or long-term persistence within an affected sector.

## Recommendation

* Enable PowerShell Script Block Logging (Event ID 4104) across the environment to capture full command execution history.
* Deploy the provided Sigma rule to detect the specific combination of Invoke-Command and -ComputerName parameters in PowerShell scripts.
* Baseline administrative activity to distinguish between legitimate remote management workflows and suspicious actor behavior.
