---
brief_id: brief-2026-11-16-wscript-cscript-suspicious-child
event_id: brief-2026-11-16-wscript-cscript-suspicious-child
revision: 1
activity_at: "2026-11-16T04:20:55Z"
title: Suspicious Child Process Spawning by WScript or CScript
slug: 2026-11-wscript-cscript-suspicious-child
description: This detection identifies suspicious child processes spawned by Windows script hosts, a technique used by adversaries and malware to execute living-off-the-land binaries, scripts, or spawn suspended processes for defense evasion.
date: "2026-11-16T04:20:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment: {}
tags:
  - attack.execution
  - attack.defense_evasion
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This technique was a common technique used by adversaries and malware to execute different LOLBIN, other scripts like PowerShell or spawn a suspended process.
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
    evidence: This technique was a common technique used by adversaries and malware to execute different LOLBIN, other scripts like PowerShell or spawn a suspended process to inject its code as a defense evasion.
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/wscript_or_cscript_suspicious_child_process.yml
  - https://www.hybrid-analysis.com/sample/8da5b75b6380a41eee3a399c43dfe0d99eeefaa1fd21027a07b1ecaa4cd96fdd?environmentId=120
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
rules:
  - title: Wscript Or Cscript Suspicious Child Process
    description: This analytic identifies suspicious processes spawned by WScript or CScript, a technique used by adversaries and malware to execute LOLBins, PowerShell, or spawn suspended processes for code injection.
    platform: sigma
    severity: medium
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

## Overview
Adversaries and malware utilize WScript (wscript.exe) and CScript (cscript.exe) to execute scripts. This behavior can involve executing living-off-the-land binaries (LOLBins), other scripts such as PowerShell, or spawning a suspended process to facilitate code injection for defense evasion.

## Attack Chain
Threat actors initiate execution via WScript or CScript, which then spawn child processes. Identified child processes in this context include regsvr32.exe, rundll32.exe, winhlp32.exe, certutil.exe, msbuild.exe, cmd.exe, powershell, pwsh.exe, wmic.exe, and mshta.exe.

## Impact
This activity may facilitate code execution, the use of living-off-the-land binaries, or process injection as part of a defense evasion strategy.

## Recommendation
Monitor for the execution of the specified child processes spawned by wscript.exe or cscript.exe. Administrators may need to filter out legitimate scripts that utilize these tools as part of their standard execution flow.
