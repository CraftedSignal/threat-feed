---
title: PowerShell Directory Enumeration via MAZE Ransomware Tactics
slug: 2026-09-powershell-directory-enumeration
description: Detection of PowerShell scripts utilizing specific cmdlets to recursively enumerate file system directories, a technique historically associated with MAZE ransomware discovery operations.
date: "2026-09-03T13:41:51Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - MAZE
tags:
  - discovery
  - ransomware
  - powershell
  - windows
  - ma-ze
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Detects technique used by MAZE ransomware to enumerate directories using Powershell
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_directory_enum.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1083/T1083.md
  - https://www.mandiant.com/resources/tactics-techniques-procedures-associated-with-maze-ransomware-incidents
rules:
  - title: Detect Suspicious Directory Enumeration via PowerShell
    description: Detects PowerShell scripts that perform recursive directory enumeration and redirect output to a file, a technique used by MAZE ransomware
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints
      owner: IT Operations
      due: 48h
      evidence: Required for visibility into script content
  hunt_leads:
    - lead: Search for high volumes of Out-File executions originating from PowerShell
      technique_id: T1083
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Common pattern for exfiltrating directory lists
  mitigation_plan:
    - priority: medium_term
      action: Implement Constrained Language Mode (CLM) via AppLocker or WDAC
      owner: IT Operations
      addresses: Restricts execution of unauthorized PowerShell functions
      evidence: Reduces post-exploitation capability
---

This detection brief addresses the use of PowerShell for unauthorized directory discovery and enumeration. Threat actors, specifically those associated with the MAZE ransomware, have been observed utilizing PowerShell scripts to map local and network file systems. By iterating through directories using cmdlets such as Get-ChildItem and redirecting the output to files, attackers can identify sensitive data for exfiltration or encryption. The technique is typically executed via living-off-the-land binaries to minimize footprint, making the monitoring of PowerShell Script Block Logging essential for identifying post-exploitation discovery activities in enterprise environments.

## Attack Chain

1. Initial access is established via phishing or exploitation of internet-facing services.
2. The attacker executes a PowerShell process via a web shell or other command-line entry point.
3. A script is invoked to enumerate directories to identify valuable data targets.
4. The script uses 'Get-ChildItem' with 'foreach' loops to recursively scan folder structures.
5. The attacker forces suppression of errors using '-ErrorAction SilentlyContinue' to prevent detection of permission issues.
6. Results of the directory scan are captured and redirected to a local text file using 'Out-File -append'.
7. The collected metadata is exfiltrated to the attacker's C2 server.
8. The final objective is reached through the subsequent encryption of identified directories.

## Impact

Successful execution of this discovery technique allows attackers to map the environment, prioritize targets for data exfiltration, and systematically prepare for the deployment of ransomware. This increases the risk of data loss and operational downtime for organizations in all sectors.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to capture the full content of executing scripts.
- Deploy the provided Sigma rule to identify common patterns of automated directory enumeration via PowerShell.
- Investigate the source of PowerShell commands that use redirection to hidden or temporary directories.
- Review and restrict execution policy for PowerShell scripts to signed or approved administrative tasks.
