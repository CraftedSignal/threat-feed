---
title: Detection of Windows Indicator Removal via Rmdir
slug: 2026-08-windows-indicator-removal-rmdir
description: Adversaries use the Windows 'rmdir' utility with recursive and quiet flags to systematically purge forensic artifacts, malware components, and temporary directories to hinder incident response efforts.
date: "2026-08-19T22:28:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - malware
  - indicator-removal
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: This activity is significant as it may indicate malware attempting to remove traces or components during cleanup operations.
    confidence_band: high
rules:
  - title: Detect Windows Indicator Removal via Rmdir
    description: Detects the execution of the 'rmdir' command with '/s' and '/q' options, a technique used by malware to remove forensic evidence and traces.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for recursive directory deletion
      owner: Detection Engineering
      due: 48h
      evidence: Source explicitly flags rmdir usage as a common indicator of malware cleanup.
  hunt_leads:
    - lead: Search for rmdir execution by non-standard parent processes in the last 30 days
      technique_id: T1070
      data_needed:
        - Process creation logs (Event ID 1 or 4688)
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Malware families like DarkGate use this for cleanup.
---

This threat brief focuses on the abuse of the native Windows `rmdir` utility by various threat actors to perform post-exploitation cleanup. Threat groups, including those deploying the DarkGate, Rustonotto, FadeStealer, Vidar Stealer, and ZOVWiper malware families, utilize the `rmdir /s /q` command sequence to recursively delete directory trees without prompting for confirmation. 

This activity is a critical indicator of defense evasion. By clearing logs, deleting staging directories, or removing malware payloads after execution, attackers attempt to minimize their footprint and thwart forensic investigation. Detection engineers should prioritize identifying this behavior when executed by processes other than standard system maintenance tools, as it often marks the conclusion of an attacker's primary objectives or the transition to a new phase of persistent operation.

## Attack Chain

1. Attacker gains initial access and executes a primary payload (e.g., Vidar Stealer or DarkGate).
2. Malware collects sensitive data or performs its primary objective.
3. Malware drops temporary configuration files or auxiliary tools to a staging directory.
4. Once the objective is reached, the malware executes `rmdir` with `/s` and `/q` flags to delete the staging directory.
5. The command line syntax `rmdir /s /q <path>` is executed to ensure silent, recursive removal.
6. The process completes, effectively removing indicators of compromise and evidence of tool execution from the disk.
7. The attacker terminates the session or moves to persistence, leaving the host in a clean state to avoid detection.

## Impact

Successful execution of indicator removal tactics significantly limits the ability of security teams to conduct post-incident forensics. By destroying the staging area and associated artifacts, attackers prevent the recovery of malware samples, configuration files, and exfiltrated data pointers. This cleanup is common across data-stealing and wiper campaigns, where the objective is either the silent exfiltration of information or the permanent destruction of host data, both of which are masked by the removal of forensic traces.

## Recommendation

1. Deploy the provided Sigma rule to your SIEM/XDR environment to detect the execution of `rmdir` with cleanup-specific flags.
2. Correlate `rmdir` activity with recent suspicious process creation events (e.g., PowerShell or unknown binaries running from `\AppData\Temp`) to identify the source of the cleanup request.
3. Exclude administrative tooling and known-good system maintenance tasks from the detection logic to reduce noise.
4. Enable command-line logging via Sysmon (Event ID 1) or Windows Security Logs (Event ID 4688) with full arguments to ensure the `/s` and `/q` flags are captured for analysis.
