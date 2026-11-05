---
brief_id: brief-2026-11-05-rjvplatform-sideloading
event_id: brief-2026-11-05-rjvplatform-sideloading
revision: 1
activity_at: "2026-11-05T12:57:51Z"
title: SystemResetPlatform DLL Sideloading
slug: 2026-11-rjvplatform-sideloading
description: Adversaries may perform DLL sideloading by placing a malicious RjvPlatform.dll in a non-default directory to be loaded by the SystemResetPlatform.exe binary.
date: "2026-11-05T12:57:51Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection rule reviewed against Sigma source.
tags:
  - persistence
  - privilege-escalation
  - execution
  - dll-sideloading
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    subtechnique_id: T1574.001
    subtechnique_name: DLL Search Order Hijacking
    evidence: Detects potential DLL sideloading of "RjvPlatform.dll" by "SystemResetPlatform.exe" located in a non-default location.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_side_load_rjvplatform_non_default_location.yml
  - https://twitter.com/0gtweet/status/1666716511988330499
rules:
  - title: Detect RjvPlatform.DLL Sideloading From Non-Default Location
    description: Detects potential DLL sideloading of RjvPlatform.dll by SystemResetPlatform.exe located in a non-default path.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
      - privilege-escalation
    techniques:
      - T1574.001
    data_sources:
      - image_load
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor SystemResetPlatform.exe image loads
      owner: Detection Engineering
      due: 48h
      evidence: Source rule definition
  hunt_leads:
    - lead: Identify executions of SystemResetPlatform.exe originating from non-Windows directories
      technique_id: T1574.001
      data_needed:
        - Process Creation (Event ID 1)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Non-default path sideloading indicator
---

This detection focuses on the unauthorized execution of the RjvPlatform.dll library by the SystemResetPlatform.exe process. DLL sideloading occurs when a legitimate application is tricked into loading a malicious library placed in a non-standard file path, potentially allowing for persistence or privilege escalation. This rule targets instances where the DLL is loaded from locations outside of the legitimate System32 directory path.

## Recommendation

Deploy the provided Sigma rule to monitor for image loads of RjvPlatform.dll by SystemResetPlatform.exe occurring from paths outside of C:\Windows\System32\SystemResetPlatform\. Investigate any instances where this process is executed from user-writable directories or temporary locations.
