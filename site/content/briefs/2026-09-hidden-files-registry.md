---
title: Detection of Registry Modifications to Disable Hidden File Visibility
slug: 2026-09-hidden-files-registry
description: Adversaries frequently modify Windows registry keys to prevent users from viewing hidden and system files, a technique used to maintain persistence and camouflage malicious artifacts.
date: "2026-09-01T12:11:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - registry
  - persistence
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: This technique is abused by several malware families to hide their files from normal users.
    confidence_band: high
rules:
  - title: Detect Registry Modification to Disable Hidden File Visibility
    description: Detects modifications to the 'Hidden' and 'ShowSuperHidden' explorer registry values used to prevent displaying hidden files and system files.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1564.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for registry-based hiding of files
      owner: Detection Engineering
      due: 48h
      evidence: Source provides Registry-based stealth TTP
  hunt_leads:
    - lead: Search for historical registry set events where 'Hidden' or 'ShowSuperHidden' were set to 0
      technique_id: T1564.001
      data_needed:
        - Windows event logs (Registry)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Common malware persistence TTP
  mitigation_plan:
    - priority: medium_term
      action: Enforce visibility settings via Group Policy (GPO) to prevent unauthorized registry modification
      owner: IT Operations
      addresses: T1564.001
      evidence: Standard security hardening
---

Adversaries often modify specific registry keys within the Windows Explorer configuration to alter how the operating system handles file visibility. By setting the 'Hidden' and 'ShowSuperHidden' registry values to zero (DWORD 0), attackers can suppress the display of hidden and protected operating system files. This modification effectively hides malicious payloads, dropped tools, and configuration files from a user's view in Windows Explorer, facilitating stealth during post-exploitation activities. This technique is commonly observed in various malware families aiming to evade manual discovery by local users. Security teams should monitor for unauthorized changes to these specific registry locations to detect potential attempts to manipulate file visibility settings as part of an attacker's evasion strategy.

## Impact

Successful exploitation of this technique allows attackers to persist and maintain a low profile on compromised systems by obscuring malicious files. This reduces the likelihood of detection by non-technical users and complicates manual incident response efforts by hiding the presence of secondary staging directories or malware binaries.

## Recommendation

Deploy detection rules to monitor for unauthorized modifications to registry keys governing hidden file display settings. 
* Implement the provided Sigma rule to alert on registry set events targeting 'Hidden' and 'ShowSuperHidden' values.
* Audit endpoints for existing configurations where hidden file visibility has been globally disabled through these registry keys.
* Correlate these registry modifications with other suspicious activities, such as unusual process creation or file system changes, to confirm malicious intent.
