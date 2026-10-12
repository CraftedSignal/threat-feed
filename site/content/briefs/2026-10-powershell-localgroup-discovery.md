---
title: Detection of PowerShell Local Group Enumeration
slug: 2026-10-powershell-localgroup-discovery
description: The execution of Get-LocalGroup via PowerShell or cmd.exe is a common discovery technique used by attackers to map local group memberships for privilege escalation.
date: "2026-10-12T17:55:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - windows
  - powershell
  - endpoint
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    evidence: The following analytic identifies the use of the get-localgroup command executed via PowerShell or cmd.exe to enumerate local groups on an endpoint.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1069/001/
  - https://github.com/redcanaryco/atomic-red-team/blob/main/atomics/T1069.001/T1069.001.md
rules:
  - title: Detect PowerShell Get-LocalGroup Execution
    description: Detects the execution of the Get-LocalGroup command via PowerShell or cmd.exe, which is often used for local group discovery.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1069.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to the SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Source provides analytic logic for local group discovery
  hunt_leads:
    - lead: Search for historical use of Get-LocalGroup in process logs
      technique_id: T1069.001
      data_needed:
        - Process command-line telemetry
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Activity is a documented discovery technique
---

The use of the Get-LocalGroup command via PowerShell or cmd.exe allows for the enumeration of local groups on a Windows endpoint. This activity is frequently observed during the discovery phase of an attack, where adversaries seek to understand local group memberships. By identifying these memberships, attackers can target specific privileged accounts to facilitate further compromise or privilege escalation. This detection focuses on monitoring process execution telemetry to identify this command line, which serves as a precursor to more malicious post-exploitation activities. Defenders should monitor for this command to identify unauthorized discovery attempts within their environment.

## Impact

Successful execution of local group discovery allows attackers to map the security posture of an endpoint, identifying high-value targets for privilege escalation. This reconnaissance can lead to unauthorized account access, lateral movement, or system-wide compromise depending on the level of permissions discovered and subsequently targeted.

## Recommendation

* Deploy the provided Sigma rule to your SIEM to monitor for Get-LocalGroup execution.
* Enable Sysmon Event ID 1 (Process Creation) and ensure full command-line arguments are captured in logs to support this detection.
* Baseline legitimate administrative activity within your environment to tune out automated scripts or authorized system management tools.
