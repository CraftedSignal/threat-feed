---
title: Monitoring Windows Defender Configuration Changes for Exclusion Additions
slug: 2026-09-windows-defender-exclusions
description: Detection of administrative or malicious modifications to Windows Defender settings that add file or path exclusions to the antimalware scanning engine.
date: "2026-09-01T12:16:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - configuration-monitoring
  - windows
affected_os:
  - Windows
rules:
  - title: Detect Windows Defender Exclusion Addition
    description: Detects the modification of Windows Defender configuration resulting in the addition of an exclusion path via Event ID 5007.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Sigma rule provided in brief
  mitigation_plan:
    - priority: medium_term
      action: Review and restrict permissions to modify Windows Defender registry keys
      owner: IT Operations
      addresses: Defender Exclusion manipulation
---

Adversaries frequently attempt to impair security software by modifying configuration settings to bypass real-time monitoring and detection capabilities. A common technique involves adding exclusion paths to Windows Defender, which prevents the antivirus engine from scanning specific files, folders, or processes. By defining these exclusions, an attacker can ensure that malicious binaries, scripts, or payloads remain undetected by the resident security software during execution or persistence. This activity is logged by the Windows Defender service upon any change to the antimalware platform configuration. Monitoring for these changes is essential to identify unauthorized modifications that may precede a larger compromise or indicate an active attempt to evade security controls.

## Impact

Successful modification of Windows Defender exclusions allows an attacker to stage and execute malicious payloads without interference from endpoint protection, effectively neutralizing one of the primary defense layers on a Windows host.

## Recommendation

* Deploy the Sigma rule below to monitor for Event ID 5007 logs, which track changes to the Windows Defender configuration.
* Establish a baseline of authorized administrative activity to reduce noise, as IT management tools may periodically update exclusion policies.
* Audit existing exclusion lists on critical infrastructure to ensure only approved, non-malicious paths are present.
