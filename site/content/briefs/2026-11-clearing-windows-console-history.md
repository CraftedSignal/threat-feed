---
brief_id: brief-2026-11-25-clearing-windows-console-history
event_id: brief-2026-11-25-clearing-windows-console-history
revision: 1
activity_at: "2026-11-25T16:26:39Z"
title: Clearing Windows Console History
slug: 2026-11-clearing-windows-console-history
description: Adversaries may clear the command history of a compromised account to conceal actions undertaken during an intrusion by using PowerShell cmdlets or deleting history files.
date: "2026-11-25T16:26:39Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - attack.stealth
  - attack.t1070
  - attack.t1070.003
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    subtechnique_id: T1070.003
    subtechnique_name: Clear Command History
    evidence: An adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion.
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_clearing_windows_console_history.yml
  - https://web.archive.org/web/20240425035922/https://stefanos.cloud/kb/how-to-clear-the-powershell-command-history/
  - https://www.shellhacks.com/clear-history-powershell/
  - https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics
rules:
  - title: Clearing Windows Console History
    description: Identifies when a user attempts to clear console history. An adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion.
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1070
      - T1070.003
    data_sources:
      - ps_script
      - windows
rules_count: 1
---

## Overview

An adversary may clear the command history of a compromised account to conceal actions undertaken during an intrusion. This can be achieved through specific PowerShell cmdlets or by removing the files where the history is stored.

## Attack Chain

1. **Execution**: Adversary executes PowerShell cmdlets (e.g., Clear-History) or removes the ConsoleHost_history.txt file.
2. **Defense Evasion**: The removal of command history prevents investigators from recovering commands executed during the post-compromise phase.

## Impact

Clearing history destroys evidence of malicious activity, such as lateral movement, credential access, or discovery commands, which hinders incident response and forensic analysis.

## Recommendation

Ensure that PowerShell Script Block Logging is enabled to capture command execution even if the console history is cleared.
