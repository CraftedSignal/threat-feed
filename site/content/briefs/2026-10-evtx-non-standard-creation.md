---
title: Monitoring Unauthorized EVTX File Creation in Non-Standard Locations
slug: 2026-10-evtx-non-standard-creation
description: Detection of Windows event log files (.evtx) created outside of standard system directories, which may indicate log tampering, data staging, or forensic evasion.
date: "2026-10-14T08:16:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - file-integrity
  - defense-evasion
affected_os:
  - Windows
references:
  - https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_create_evtx_non_common_locations.yml
rules:
  - title: Detect EVTX File Created In Non-Standard Location
    description: Detects the creation of new files with the .evtx extension in locations other than the standard Windows system event log directories.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for .evtx files in non-system directories
      technique_id: T1685
      data_needed:
        - File creation telemetry
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Creation of new files with the .evtx extension in non-common locations.
---

This brief addresses the security monitoring of Windows Event Log (.evtx) file creation. Threat actors and adversaries often attempt to manipulate, clear, or exfiltrate security logs to mask malicious activities, hinder incident response, or perform offline analysis of system event data. While logs are traditionally stored within the 'C:\Windows\System32\winevt\Logs\' directory, malicious actors may redirect logging output or manually copy log files to obscure locations to facilitate staging before exfiltration or to bypass file integrity monitors that may not be configured to audit non-standard directories. Defenders should differentiate between legitimate administrative backup procedures, system-generated temporary logs, and potentially unauthorized file creation events.

## Impact

Successful log tampering or unauthorized access to event data can lead to a complete loss of visibility into post-compromise activity. If an attacker successfully stages or modifies logs, they can hide evidence of initial access, lateral movement, or privilege escalation. This visibility gap significantly increases the dwell time of an adversary and complicates the reconstruction of the attack timeline during a forensic investigation.

## Recommendation

Deploy the provided Sigma rule to identify anomalous .evtx file creation events across the environment. 

- Ensure that Sysmon or equivalent EDR file-event monitoring is configured to audit file creation events for files ending in ".evtx".
- Baseline common administrative backup tools and authorized software that may legitimately create logs in non-standard locations to reduce noise.
- Investigate any .evtx file creation in user-writable directories (e.g., C:\Users\, C:\ProgramData\ except for legitimate system paths) as these are high-probability indicators of unauthorized log manipulation.
