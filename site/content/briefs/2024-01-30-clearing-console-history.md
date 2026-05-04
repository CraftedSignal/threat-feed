---
title: Windows Console History Clearing
slug: 2024-01-30-clearing-console-history
description: Adversaries may clear the command history of a compromised account to conceal the actions undertaken during an intrusion on a Windows system.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - powershell
  - windows
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - M365 Defender
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://stefanos.cloud/kb/how-to-clear-the-powershell-command-history/
  - https://www.shellhacks.com/clear-history-powershell/
  - https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics
rules:
  - title: Detect Clearing PowerShell History
    description: Detects the use of Clear-History cmdlet to clear the PowerShell command history.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Removal of PowerShell History File
    description: Detects the use of Remove-Item or rm command against the PowerShell history file.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can try to cover their tracks by clearing the PowerShell console history on Windows systems. PowerShell offers multiple ways to log commands, including the built-in history and the command history managed by the PSReadLine module. This activity is often part of post-compromise behavior aimed at evading detection and forensic analysis. This rule detects the execution of specific commands that clear the built-in PowerShell logs or delete the `ConsoleHost_history.txt` file. The rule focuses on PowerShell activity and covers scenarios where commands like Clear-History, Remove-Item, rm, and Set-PSReadlineOption are used to manipulate command history.

## Attack Chain

1.  Initial access is gained through an unspecified method, potentially exploiting a vulnerability or using stolen credentials.
2.  The attacker executes PowerShell (powershell.exe, pwsh.exe, or powershell_ise.exe) to perform reconnaissance and other malicious activities.
3.  The attacker attempts to clear the PowerShell command history using the `Clear-History` cmdlet.
4.  Alternatively, the attacker attempts to remove the `ConsoleHost_history.txt` file using `Remove-Item` or `rm`, which stores the PSReadLine command history.
5.  Another method involves using the `Set-PSReadlineOption` cmdlet with the `SaveNothing` parameter to prevent the saving of future command history.
6. The attacker may leverage other tools and techniques to further obscure their activities and maintain persistence on the compromised system.
7. The attacker attempts to move laterally to other systems within the network to increase their impact.
8. The final objective is data exfiltration, deployment of ransomware, or other malicious activities, all while attempting to evade detection by clearing logs and command history.

## Impact

Successful clearing of console history hinders forensic investigations and incident response efforts. If command history is cleared, administrators will have difficulty reconstructing the attacker's actions and identifying the extent of the compromise. This can lead to prolonged incident response times, increased damage, and potential for further exploitation of the compromised systems.

## Recommendation

*   Deploy the Sigma rule `Detect Clearing PowerShell History` to your SIEM to detect the use of `Clear-History` cmdlet, potentially indicating an attempt to remove command history.
*   Deploy the Sigma rule `Detect Removal of PowerShell History File` to detect the use of `Remove-Item` or `rm` command against the PowerShell history file.
*   Enable PowerShell logging and auditing policies to ensure adequate visibility into PowerShell activity as described in the [setup instructions](https://ela.st/audit-process-creation) to improve detection capabilities.
