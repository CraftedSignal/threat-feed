---
title: Detection of Sdclt UAC Bypass via Process Spawning
slug: 2026-09-sdclt-uac-bypass
description: The Windows utility sdclt.exe is frequently leveraged by threat actors to perform User Account Control (UAC) bypass by spawning unauthorized child processes with elevated privileges.
date: "2026-09-01T12:24:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - windows
  - uac-bypass
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: This could be an indicator of sdclt being used for bypass UAC techniques.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_sdclt_child_process.yml
  - https://github.com/OTRF/detection-hackathon-apt29/issues/6
  - https://github.com/OTRF/ThreatHunter-Playbook/blob/2d4257f630f4c9770f78d0c1df059f891ffc3fec/docs/evals/apt29/detections/3.B.2_C36B49B5-DF58-4A34-9FE9-56189B9DEFEA.md
rules:
  - title: Detect Sdclt Child Processes
    description: Detects instances where sdclt.exe spawns a child process, a common indicator of UAC bypass exploitation.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1548.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sdclt Child Processes detection rule to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: This behavior is a high-signal indicator of UAC bypass.
  hunt_leads:
    - lead: Search for instances of sdclt.exe spawning non-standard child processes in the last 30 days.
      technique_id: T1548.002
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source indicates sdclt child process spawning is a known indicator of UAC bypass.
---

The Windows Backup and Restore application, `sdclt.exe`, is a binary that runs with auto-elevated privileges. Threat actors have historically abused this binary to perform UAC bypass techniques. By manipulating specific registry keys (typically related to `Shell\Open\command` in the registry hive associated with the application's configuration), an attacker can force `sdclt.exe` to execute an arbitrary payload or process. Because the parent process `sdclt.exe` is auto-elevated, the resulting child process inherits these administrative privileges, effectively bypassing the UAC prompt that would otherwise appear when executing privileged tasks. This technique is a well-documented method for privilege escalation on Windows systems and remains a relevant behavioral indicator for security operations centers monitoring for suspicious process lineage.

## Attack Chain

1. Attacker identifies a target system where code execution is already achieved at a medium-integrity level.
2. Attacker modifies specific registry keys (e.g., `HKCU\Software\Classes\Folder\shell\open\command`) to point to a malicious binary or script.
3. Attacker executes `sdclt.exe` via command line or scheduled task.
4. The operating system launches `sdclt.exe` due to its auto-elevation manifest.
5. `sdclt.exe` accesses the manipulated registry key to determine its startup behavior.
6. `sdclt.exe` spawns the attacker-controlled binary as a child process.
7. The child process executes with high-integrity (administrative) permissions.
8. Attacker achieves local privilege escalation to perform post-exploitation activities.

## Impact

Successful exploitation of this technique allows an attacker to transition from a standard user context to an administrative context without triggering a UAC prompt. This escalation is a critical step in maintaining persistence, dumping credentials from memory (e.g., LSASS access), or installing rootkits, ultimately leading to full system compromise.

## Recommendation

1. Deploy the provided Sigma rule to monitor for any child processes spawned by `sdclt.exe`, as this behavior is rare in standard administrative environments.
2. Baseline your environment to identify legitimate uses of `sdclt.exe`. In most enterprise environments, `sdclt.exe` should not be spawning child processes.
3. Monitor registry modifications targeting the `Classes\Folder\shell\open\command` paths if high-value endpoints show signs of compromise.
