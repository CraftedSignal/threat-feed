---
brief_id: brief-2026-11-10-powersploit-empire-tasks
event_id: brief-2026-11-10-powersploit-empire-tasks
revision: 1
activity_at: "2026-11-10T02:51:05Z"
title: 'HackTool: Default PowerSploit and Empire scheduled task persistence'
slug: 2026-11-powersploit-empire-tasks
description: PowerSploit and Empire utilize predictable command-line patterns when creating scheduled tasks for persistence, which can be identified via process creation telemetry.
date: "2026-11-10T02:51:05Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Ready for deployment.
tags:
  - persistence
  - windows
  - hacktool
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053.005
    technique_name: Scheduled Task
    evidence: The modules leverage schtasks.exe to create persistent execution triggers.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: The persistence mechanism relies on PowerShell execution triggered by the task.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_hktl_powersploit_empire_default_schtasks.yml
  - https://github.com/PowerShellMafia/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1
  - https://github.com/EmpireProject/Empire/blob/08cbd274bef78243d7a8ed6443b8364acd1fc48b/lib/modules/powershell/persistence/userland/schtasks.py
rules:
  - title: Detect Default PowerSploit/Empire Scheduled Task Creation
    description: Detects the creation of scheduled tasks using default parameters associated with PowerSploit or Empire persistence modules.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1053.005
      - T1059.001
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
    - action: Deploy Sigma rule 56c217c3-2de2-479b-990f-5c109ba8458f to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Rule provides high-fidelity detection for documented framework defaults.
  hunt_leads:
    - lead: Hunt for scheduled tasks named "Updater" or containing "-NonI" and "powershell" in the command line.
      technique_id: T1053.005
      data_needed:
        - Endpoint scheduled task inventory or process creation telemetry
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: PowerSploit and Empire utilize "Updater" as a default task name.
---

PowerSploit and Empire frameworks include modules for maintaining persistence on compromised Windows systems by creating scheduled tasks. These modules often employ default naming conventions and execution flags, specifically targeting task names like 'Updater' and executing PowerShell commands with non-interactive flags. This behavior is observable through process creation logs when `schtasks.exe` is spawned by `powershell.exe` or `pwsh.exe` with specific command-line arguments.

## Impact

Successful execution of these modules establishes persistence, allowing attackers to maintain access across system reboots or user logons without requiring manual re-exploitation.

## Recommendation

- Deploy the provided Sigma rule to detect the use of default persistence task creation patterns.
- Audit existing scheduled tasks for entries named 'Updater' that execute encoded or base-level PowerShell scripts.
- Review environment-wide use of `schtasks.exe` spawned by PowerShell to identify potentially unauthorized persistence mechanisms.
