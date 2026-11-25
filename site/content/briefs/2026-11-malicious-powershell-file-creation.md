---
brief_id: brief-2026-11-25-malicious-powershell-file-creation
event_id: brief-2026-11-25-malicious-powershell-file-creation
revision: 1
activity_at: "2026-11-25T16:23:50Z"
title: Detection of Offensive PowerShell Scripts via File Creation
slug: 2026-11-malicious-powershell-file-creation
description: This detection brief identifies the presence of known offensive PowerShell exploitation scripts on Windows endpoints by monitoring for the creation of specific, high-risk script filenames.
date: "2026-11-25T16:23:50Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "3"
  rating: A3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection rule syntax and context match documented community standards.
tags:
  - attack.execution
  - attack.t1059.001
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.001
    subtechnique_name: PowerShell
    evidence: Detects the creation of known offensive powershell scripts used for exploitation
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_powershell_exploit_scripts.yml
rules:
  - title: Detect Known Offensive PowerShell Exploitation Scripts
    description: Detects the creation of files on disk matching known offensive PowerShell scripts used in exploitation, reconnaissance, and post-exploitation activities.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable File System object auditing or Sysmon EID 11 to capture file creation events.
      owner: Detection Engineering
      due: 48h
      evidence: Detection rule logsource requires file_event category telemetry.
  hunt_leads:
    - lead: Search for files created in common staging directories (Temp, Public, AppData) that contain strings matching known offensive tool naming patterns.
      technique_id: T1059.001
      data_needed:
        - File creation logs
        - Process command line arguments
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The Sigma rule lists numerous offensive filenames that are rarely used in legitimate administrative contexts.
---

## Overview

Security teams can detect the staging of common offensive PowerShell frameworks and exploitation scripts by monitoring file system events. This detection identifies the creation of files matching known malicious PowerShell script names, including tools used for credential dumping, persistence, UAC bypass, and network reconnaissance.

## Recommendation

Deploy the provided Sigma detection rule to monitor for file creation events matching the identified list of offensive script names. This is particularly effective for detecting the 'drop' phase of an engagement where an attacker stages tools on the disk. Ensure endpoint security policies restrict write access to non-standard directories to reduce the footprint of potential tool staging.
