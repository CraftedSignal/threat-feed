---
title: Detection of Automated PowerShell Data Collection
slug: 2026-09-automated-collection-powershell
description: Adversaries utilize automated PowerShell scripts to locate and gather sensitive documents across local file systems for subsequent exfiltration.
date: "2026-09-03T13:37:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - collection
  - powershell
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
    evidence: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_automated_collection.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md
rules:
  - title: Detect Automated PowerShell Data Collection
    description: Detects the use of PowerShell to recursively search for common document file types, an indicator of automated data collection.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1119
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104)
      owner: IT Operations
      due: 48h
      evidence: Required for visibility into script-based collection TTPs
  hunt_leads:
    - lead: Search for high-frequency Get-ChildItem calls with recursive flags in logs
      technique_id: T1119
      data_needed:
        - PowerShell Operational Event Log
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Automated collection requires recursive file enumeration
  mitigation_plan:
    - priority: medium
      action: Implement strict Execution Policy and AppLocker/WDAC rules
      owner: IT Operations
      addresses: Restricts execution of unauthorized PowerShell scripts
      evidence: Reduces potential for post-compromise tooling
---

Adversaries often perform automated data collection to identify valuable information after gaining initial access to a compromised environment. By leveraging the built-in PowerShell capability 'Get-ChildItem', attackers can recursively search directories for specific file extensions associated with documents, such as .docx, .xlsx, .pdf, or .rtf. This technique allows for rapid discovery and staging of data without the need for manual browsing. Defenders should monitor for PowerShell scripts that combine recursive directory traversal with file-type filtering, as this pattern is a common indicator of automated reconnaissance and collection activity preceding exfiltration.

## Attack Chain

1. Initial access is established on the Windows host via spearphishing or exploit.
2. The attacker opens a PowerShell session to execute discovery commands.
3. The adversary identifies a target directory for data harvesting.
4. The Get-ChildItem cmdlet is invoked with -Recurse and -Include parameters.
5. The command filters the search for specific document extensions (e.g., .docx, .pdf).
6. The system iterates through subdirectories to collect a list of target files.
7. Results are piped or redirected to a temporary staging file on the disk.
8. Collected files are compressed or prepared for exfiltration to an external C2 server.

## Impact

Successful execution of automated collection allows an attacker to gain visibility into an organization's proprietary data, intellectual property, and sensitive user documentation. This stage is a prerequisite for data theft, which can lead to significant business disruption, regulatory penalties, and loss of competitive advantage.

## Recommendation

1. Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints to capture full command execution history.
2. Deploy the provided Sigma rule to detect recursive file searches targeting document extensions.
3. Investigate any PowerShell processes triggered by unexpected parent processes (e.g., web server services or document editors).
4. Review generated PowerShell logs for attempts to copy or move large volumes of files identified during the collection process.
