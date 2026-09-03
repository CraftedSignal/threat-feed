---
title: Suspicious PowerShell Reconnaissance and Data Export
slug: 2026-09-powershell-recon-export
description: Adversaries utilize automated PowerShell reconnaissance commands combined with redirection to temporary files to collect and stage system information for exfiltration.
date: "2026-09-03T13:42:54Z"
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
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_recon_export.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md
rules:
  - title: Detect Recon Information for Export with PowerShell
    description: Detects reconnaissance commands that redirect output to the temp directory
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
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104)
      owner: IT Operations
      due: 48h
      evidence: Log source requirement for the provided detection rule
  hunt_leads:
    - lead: Search for script block logs containing both enumeration cmdlets and redirection operators
      technique_id: T1119
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source rule logic
---

Adversaries often perform automated reconnaissance to gather environment-specific data after gaining initial access to a Windows system. A common technique involves executing native PowerShell cmdlets to enumerate services, running processes, or file system contents and redirecting the output into text files within the user's temporary directory. This behavior facilitates the staging of sensitive internal system information for later exfiltration. Defenders should focus on monitoring PowerShell Script Block logs (Event ID 4104) for suspicious combinations of enumeration commands and redirection operators pointing to standard temporary file paths.

## Attack Chain

1. Attacker gains initial access to the target host through phishing or exploit.
2. Attacker launches PowerShell to perform discovery of local assets.
3. PowerShell cmdlets (Get-Service, Get-ChildItem, Get-Process) are executed to map system state.
4. Output is piped or redirected using the '>' operator into a file in $env:TEMP.
5. The attacker verifies the content of the staged text file.
6. The staged data is exfiltrated to attacker-controlled infrastructure.

## Impact

Successful reconnaissance allows an attacker to map the victim environment, identify security software, find sensitive data locations, and prepare for lateral movement or data exfiltration. If left undetected, this activity significantly increases the success rate of subsequent phases of an attack.

## Recommendation

Deploy the provided Sigma rule to detect suspicious PowerShell enumeration patterns and enable PowerShell Script Block Logging (Event ID 4104) across all endpoints to ensure visibility.
