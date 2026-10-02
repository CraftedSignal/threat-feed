---
title: Detection of Renamed Schtasks Execution
slug: 2026-10-renamed-schtasks-execution
description: Threat actors may rename the legitimate schtasks.exe Windows utility to evade security monitoring while establishing persistence or executing tasks.
date: "2026-10-02T11:13:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - execution
  - stealth
  - windows
  - process-creation
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053.005
    technique_name: 'Scheduled Task/Job: Scheduled Task'
    evidence: One of the very common persistence techniques is schedule malicious tasks using schtasks.exe.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036.003
    technique_name: 'Masquerading: Rename System Utilities'
    evidence: To evade detection, threat actors may rename the schtasks.exe binary to schedule their malicious tasks.
    confidence_band: high
rules:
  - title: Detect Renamed Schtasks Execution
    description: Detects the execution of a renamed schtasks.exe binary by identifying common scheduling command-line arguments on non-standard binary names or mismatched original file metadata.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1036.003
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Renamed Schtasks Execution Sigma rule to SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Source provides detection logic for malicious schtasks.exe renaming.
  hunt_leads:
    - lead: Search for process execution where Image name is not schtasks.exe but CommandLine contains common task scheduling switches.
      technique_id: T1036.003
      data_needed:
        - Process creation logs with CommandLine and Image fields
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Technique relies on renaming binaries to evade standard detection.
---

Threat actors frequently leverage the legitimate Windows 'schtasks.exe' utility to establish persistence, execute malicious payloads, or achieve privilege escalation by scheduling tasks. Because this binary is heavily monitored by EDR and SIEM solutions, adversaries often employ evasion techniques, such as renaming the binary to a different filename to bypass basic file-path or process-name detection rules. Defenders must monitor for processes that exhibit command-line arguments consistent with schtasks.exe (such as '/create', '/delete', or '/run') while utilizing an image path that does not reflect the standard 'schtasks.exe' filename, or by checking the original file metadata when available in logs.

## Impact

Successful abuse of scheduled tasks allows an attacker to maintain long-term persistence within a compromised environment, execute malicious code with system or user-level privileges, and automate post-exploitation tasks. If undetected, this can lead to broad system compromise and successful exfiltration or ransomware deployment.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious process execution patterns that deviate from expected schtasks.exe behavior. Focus tuning on identifying non-standard filenames that invoke task-scheduling flags. Ensure that Sysmon or equivalent EDR telemetry includes both the image path and original file metadata (from the PE header) to detect renamed binaries reliably.
