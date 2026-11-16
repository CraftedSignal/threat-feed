---
brief_id: brief-2026-11-16-cmd-script-execution
event_id: brief-2026-11-16-cmd-script-execution
revision: 1
activity_at: "2026-11-16T04:19:09Z"
title: Windows CMD spawning script interpreters from non-standard directories
slug: 2026-11-cmd-script-execution
description: Adversaries may use cmd.exe to launch script interpreters such as cscript.exe or wscript.exe from user-writable directories to execute malicious scripts while avoiding standard system paths.
date: "2026-11-16T04:19:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - attack.execution
  - attack.t1059.003
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: The following detects the execution of cscript.exe or wscript.exe processes spawned by cmd.exe
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/detect_use_of_cmd_exe_to_launch_script_interpreters.yml
  - https://attack.mitre.org/techniques/T1059/
rules:
  - title: Detect Use of cmd exe to Launch Script Interpreters
    description: Detects the execution of cscript.exe or wscript.exe processes spawned by cmd.exe, specifically focusing on executions originating from non-system directories while filtering out service accounts (ending in '$') and known system paths.
    platform: sigma
    severity: medium
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

## Overview
The following detects the execution of cscript.exe or wscript.exe processes spawned by cmd.exe, leveraging EDR telemetry to identify potential malicious script execution from user-writable directories such as Users, AppData, Temp, and Downloads. This detection excludes trusted system paths (C:\Windows\System32\, C:\Windows\SysWOW64\, C:\Program Files\, and C:\Program Files (x86)\) and filters out service accounts (accounts ending with $) to minimize noise from automated processes.

## Attack Chain
This activity involves cmd.exe spawning a script interpreter (cscript.exe or wscript.exe). Adversaries often use non-standard, user-writable directories to stage scripts to evade detection focused on typical system locations.

## Impact
Execution of arbitrary scripts on the host may lead to unauthorized code execution and further compromise of the endpoint.

## Recommendation
Monitor endpoint process creation telemetry for instances of cscript.exe or wscript.exe where the parent process is cmd.exe. Investigate executions originating from non-standard or user-writable paths. Note that false positives may occur due to legitimate administrative activity, logon scripts, or software deployment tools (e.g., SCCM, Intune).
