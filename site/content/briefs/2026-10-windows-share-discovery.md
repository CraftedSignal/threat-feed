---
title: Detection of Network File Share Discovery via PowerView
slug: 2026-10-windows-share-discovery
description: Attackers utilize the PowerView 'Invoke-ShareFinder' PowerShell cmdlet to discover network file shares, potentially exposing sensitive data for lateral movement and privilege escalation.
date: "2026-10-12T18:07:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - lateral-movement
  - powershell
  - active-directory
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1135
    technique_name: Network Share Discovery
    evidence: The following analytic detects the execution of the Invoke-ShareFinder PowerShell cmdlet from PowerView.
    confidence_band: high
rules:
  - title: Detect PowerView Invoke-ShareFinder Execution
    description: Detects execution of the PowerView Invoke-ShareFinder cmdlet via PowerShell Script Block Logging
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1135
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) via GPO
      owner: IT Operations
      due: 72h
      evidence: Required to capture the detection signal
    - action: Deploy Sigma rule for Invoke-ShareFinder to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Provided rule definition
  hunt_leads:
    - lead: Search historic 4104 logs for Invoke-ShareFinder
      technique_id: T1135
      data_needed:
        - Powershell Script Block Logging (4104)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Technique is highly specific to discovery tools
---

This threat brief details the detection of the 'Invoke-ShareFinder' cmdlet, a component of the PowerView framework commonly used by threat actors for internal network reconnaissance. PowerView is a PowerShell-based toolset designed to facilitate the discovery and enumeration of Active Directory environments. By executing 'Invoke-ShareFinder', an attacker can map accessible network file shares across an organization's environment. This discovery process is a critical pre-cursor to lateral movement and data exfiltration, as it allows adversaries to identify targets containing backups, sensitive documentation, hardcoded credentials, or automation scripts. Defenders must monitor PowerShell execution patterns to identify the use of such enumeration tools, particularly when executed by non-administrative users or from workstations where such activity is anomalous.

## Impact

Successful reconnaissance via 'Invoke-ShareFinder' significantly lowers the barrier for attackers to identify and access high-value targets within a network. Organizations are at risk of unauthorized access to proprietary data, intellectual property, and credential theft, which can subsequently lead to broader network compromise, ransomware deployment, or long-term persistence within the target environment.

## Recommendation

* Enable PowerShell Script Block Logging (Event ID 4104) across all organizational endpoints to ensure visibility into script execution.
* Deploy the Sigma rule below to detect and alert on the usage of PowerView's share discovery functionality.
* Baseline the usage of administrative PowerShell frameworks to identify and whitelist legitimate operational requirements, reducing noise for SOC analysts.
