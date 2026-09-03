---
title: Detection of Offensive PowerShell Script Execution via Module Logging
slug: 2026-09-malicious-powershell-scripts
description: This brief documents a comprehensive set of offensive PowerShell script names and execution patterns frequently used by threat actors for reconnaissance, credential harvesting, and lateral movement, detectable via PowerShell Module Logging.
date: "2026-09-03T13:37:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - credential-access
  - discovery
  - execution
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The rule identifies the execution of known offensive PowerShell scripts used for exploitation or reconnaissance.
    confidence_band: high
rules:
  - title: Detect Known Offensive PowerShell Script Execution
    description: Detects the execution of known offensive PowerShell scripts used for exploitation or reconnaissance via PowerShell Module Logging.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - ps_module
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to detect offensive PowerShell scripts.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides list of known offensive scripts.
  hunt_leads:
    - lead: Search for script names in historical Event ID 4103 logs.
      technique_id: T1059.001
      data_needed:
        - Event ID 4103
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Script names in source are known to be used by attackers.
  mitigation_plan:
    - priority: medium_term
      action: Implement PowerShell Constrained Language Mode (CLM).
      owner: IT Operations
      addresses: T1059.001
      evidence: Reduces efficacy of PowerShell-based offensive tooling.
---

This brief catalogs common offensive PowerShell scripts utilized by various threat actors to facilitate post-exploitation activities. These scripts span a wide array of capabilities, including credential dumping (e.g., Mimikatz wrappers, Get-PassHashes), reconnaissance (e.g., PowerView, PowerUp), lateral movement (e.g., Invoke-PsExec), and persistence establishment. Because these tools are widely used across multiple campaigns, detection engineering teams should focus on PowerShell Module Logging (Event ID 4103/4104) to identify the invocation of these specific script names within the environment. Detecting these signatures provides visibility into active threat actor activity during the post-compromise phase, regardless of the initial entry vector. Defenders should prioritize identifying these scripts in non-administrative contexts or when executed by unexpected parent processes.

## Impact

Successful execution of these scripts grants attackers significant visibility into internal networks, the ability to escalate privileges to domain administrator levels, and the capability to exfiltrate sensitive data or deploy ransomware. These scripts are frequently observed in the toolsets of groups such as Black Basta and actors utilizing frameworks like PowerSploit, Nishang, and WinPwn.

## Recommendation

- Enable PowerShell Module Logging (Event ID 4103) and Script Block Logging (Event ID 4104) across all Windows endpoints to capture script execution context.
- Deploy the provided Sigma rule to monitor for the execution of these specific offensive script names.
- Establish alerting for these scripts when executed by non-IT or non-security service accounts.
- Integrate PowerShell logs with a SIEM and trigger high-priority alerts when these known offensive scripts are detected.
