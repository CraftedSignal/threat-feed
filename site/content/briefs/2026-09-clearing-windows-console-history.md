---
title: Detection of Windows Console History Clearing
slug: 2026-09-clearing-windows-console-history
description: Adversaries often attempt to clear PowerShell command history to conceal malicious activities conducted during a security incident.
date: "2026-09-03T12:35:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - anti-forensics
  - powershell
  - stealth
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: An adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion.
    confidence_band: high
references:
  - https://stefanos.cloud/blog/kb/how-to-clear-the-powershell-command-history/
  - https://www.shellhacks.com/clear-history-powershell/
  - https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics
rules:
  - title: Detect PowerShell Console History Clearing
    description: Identifies attempts to clear PowerShell console history using Clear-History cmdlet or manual file deletion of ConsoleHost_history.txt.
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1070.003
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoint assets.
      owner: IT Operations
      due: 48h
      evidence: Source requirement for detection
    - action: Deploy the Sigma detection rule to monitor for history deletion events.
      owner: Detection Engineering
      due: 72h
      evidence: Sigma rule provided in brief
  hunt_leads:
    - lead: Search historical logs for evidence of Clear-History or file deletion of history paths.
      technique_id: T1070.003
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this as a method to conceal intrusion
  mitigation_plan:
    - priority: medium_term
      action: Restrict user execution permissions to prevent the removal of log files.
      owner: IT Operations
      addresses: T1070.003
      evidence: General security best practice
---

Adversaries frequently employ anti-forensic techniques to hinder post-incident investigations by erasing evidence of their presence on a compromised host. One common objective is the removal of the PowerShell command history, which logs executed commands and script interactions. By deleting the 'ConsoleHost_history.txt' file or executing the 'Clear-History' cmdlet, attackers aim to prevent defenders from reconstructing the timeline of their actions, such as C2 communication, lateral movement, or data staging. This activity is a classic indicator of an attacker attempting to cover their tracks before disconnecting from the environment. Defenders should monitor for these specific command patterns in PowerShell Script Block logs to identify potential attempts to destroy forensic evidence.

## Impact

Successful execution of console history clearing significantly degrades the ability of incident response teams to perform root cause analysis, identify the scope of the compromise, and recover sensitive information about the attacker's TTPs within the environment.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) to capture the full command content of executed scripts.
- Deploy the provided Sigma rule to your SIEM and alert on instances of manual history deletion or clearing command patterns.
- Baseline administrative scripts that might perform log maintenance to reduce false positives.
