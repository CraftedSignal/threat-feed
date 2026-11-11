---
brief_id: brief-2026-11-11-defender-context-menu-removal
event_id: brief-2026-11-11-defender-context-menu-removal
revision: 1
activity_at: "2026-11-11T07:32:41Z"
title: 'Defense Impairment: Removal of Windows Defender context menu'
slug: 2026-11-defender-context-menu-removal
description: Adversaries may remove the "Scan with Microsoft Defender" context menu handler to hinder manual security scans and reduce the visibility of security products.
date: "2026-11-11T07:32:41Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - defense-impairment
  - windows
  - registry
  - defense-evasion
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_defender_remove_context_menu.yml
  - https://research.splunk.com/endpoint/395ed5fe-ad13-4366-9405-a228427bdd91/
rules:
  - title: Detect Windows Defender Context Menu Handler Removal
    description: Detects the use of reg.exe or PowerShell to delete the Windows Defender context menu handler registry keys, which removes the Scan option from the context menu.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect defense impairment activity.
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in source.
  hunt_leads:
    - lead: Search for processes (PowerShell, reg.exe) interacting with registry keys containing 'ContextMenuHandlers' and 'EPP'.
      technique_id: T1685
      data_needed:
        - Process creation logs with command line arguments
        - Registry modification events (Sysmon EID 12/13)
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source documentation of registry paths targeted for deletion.
---

Attackers use system utilities, including reg.exe and PowerShell, to delete specific registry keys associated with the Windows Defender shell extension. This action removes the "Scan with Microsoft Defender" option from the Windows right-click context menu for files, directories, and drives. This technique is used to obstruct manual, on-demand scanning by users or administrators.

## Impact
Removing the context menu handler limits the ease of manual security scanning, which can delay the detection of malicious files during an active intrusion.

## Recommendation
- Deploy detection for registry modifications related to Windows Defender context menu keys.
- Monitor for administrative script execution that invokes removal commands against security-related registry paths.
- Investigate any host where the context menu for Windows Defender has been disabled, as this is highly abnormal in a managed enterprise environment.
