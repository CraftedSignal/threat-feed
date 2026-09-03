---
title: Windows Screen Capture via PowerShell CopyFromScreen
slug: 2026-09-windows-screen-capture
description: Adversaries use the .NET CopyFromScreen method within PowerShell scripts to capture desktop screenshots for information gathering during post-compromise operations.
date: "2026-09-03T13:37:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - collection
  - reconnaissance
  - powershell
  - endpoint-monitoring
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
    evidence: Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.
    confidence_band: high
rules:
  - title: Detect Windows Screen Capture using CopyFromScreen
    description: Detects PowerShell scripts attempting to capture screen images using the .NET CopyFromScreen method
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1113
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
    - action: Deploy Sigma detection for .CopyFromScreen
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific string trigger
  hunt_leads:
    - lead: Search PowerShell Script Block logs for .CopyFromScreen
      technique_id: T1113
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Technique is a known method for gathering screen data
---

Adversaries frequently employ screen capture techniques to exfiltrate sensitive data or monitor user activity following an initial compromise. A common, lightweight method observed in post-compromise operations involves the abuse of .NET classes available within the PowerShell environment. Specifically, attackers utilize the 'CopyFromScreen' method of the 'System.Drawing.Graphics' class to programmatically capture the desktop and save it as an image file. This technique is often integrated into custom remote access tools or lightweight reconnaissance scripts to avoid the overhead of deploying full-featured malware. Because it leverages built-in Windows APIs via PowerShell, defenders can detect this activity by monitoring PowerShell Script Block Logging for the instantiation of these specific graphics classes.

## Impact

Successful execution allows attackers to exfiltrate sensitive information visible on the victim's screen, such as credentials, internal documentation, or ongoing communications. This collection phase is a critical step in reconnaissance and exfiltration workflows, increasing the risk of data exposure for the compromised host.

## Recommendation

* Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to ensure the visibility of script content.
* Deploy the provided Sigma rule to detect the use of the .CopyFromScreen method in PowerShell scripts.
* Establish an alert for PowerShell execution where the script content references 'System.Drawing.Graphics'.
* Audit environments for administrative or non-standard tools that may legitimately perform screen captures.
