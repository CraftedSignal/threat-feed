---
title: Detection of Shell Application File Write Operations to Suspicious Directories
slug: 2026-09-windows-shell-write-suspicious
description: Detection of Windows shell and scripting applications writing files to common staging directories used by threat actors for persistence and lateral movement.
date: "2026-09-01T12:17:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - execution
  - defensive-evasion
  - file-system
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects Windows shells and scripting applications that write files to suspicious folders
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_shell_write_susp_directory.yml
rules:
  - title: Detect Windows Shell and Scripting File Write to Suspicious Directory
    description: Detects Windows shells, scripting applications, and utility binaries that write files to suspicious or commonly abused folders like C:\Users\Public\, C:\PerfLogs\, and C:\Windows\Temp\
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the provided Sigma rule to SIEM environment.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides detection logic for suspicious file writes
  mitigation_plan:
    - priority: medium_term
      action: Restrict write permissions for non-privileged accounts on C:\Users\Public and C:\PerfLogs directories.
      owner: IT Operations
      addresses: T1059
      evidence: Hardening these directories reduces staging opportunities for attackers
---

This threat brief focuses on detecting the usage of Windows shell and scripting binaries that interact with directories typically associated with malicious staging and file persistence. Threat actors frequently utilize folders such as C:\Users\Public\, C:\PerfLogs\, and C:\Windows\Temp\ to drop secondary payloads, stage exfiltration data, or maintain persistence through scheduled tasks or autoruns. Because these directories often allow read/write access to non-privileged users or are frequently overlooked by administrators, they are prime targets for malicious activity. Defenders monitoring file system events can identify suspicious process-to-directory interactions by flagging shells (like PowerShell or cmd.exe) or utility binaries (like certutil or mshta) that perform file write operations within these locations.

## Impact

Successful file staging in these directories often precedes second-stage malware deployment, lateral movement, or unauthorized data exfiltration. If left unmonitored, these paths serve as reliable "safe harbors" for attackers to drop tools that might otherwise trigger security alerts if placed in more restrictive or sensitive system directories.

## Recommendation

Deploy file system monitoring on endpoints to identify processes writing to public-facing or sensitive directories. 

- Enable Sysmon (Event ID 11) or equivalent Endpoint Detection and Response (EDR) file-write event logging.
- Deploy the provided Sigma rule to your SIEM to alert on shell activity targeting the identified directories.
- Review baseline activity in your environment to distinguish between automated administrative scripts and unauthorized process file writes.
