---
title: Detection of Timestomping on Windows Executables
slug: 2026-08-timestomp-detection
description: Detection and mitigation guidance for identifying timestomping activity where adversaries modify creation timestamps of executable files in sensitive system directories to evade detection.
date: "2026-08-24T15:48:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Adversaries may modify file time attributes to blend malicious executables with legitimate system files.
    confidence_band: high
rules:
  - title: Potential Timestomp in Executable Files
    description: Identifies the modification of a file creation time for executable files in sensitive system directories.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.006
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
    - action: Enable Sysmon Event ID 2 on endpoint assets
      owner: IT Operations
      due: 72h
      evidence: Required for the rule to trigger
  hunt_leads:
    - lead: Search for files with creation dates significantly older than the OS installation date
      technique_id: T1070.006
      data_needed:
        - File system metadata logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Timestomping is used to mimic older files
  mitigation_plan:
    - priority: medium_term
      action: Review and restrict write permissions in System32 and Startup directories
      owner: IT Operations
      addresses: T1070.006
      evidence: Limits unauthorized file modification
---

Adversaries frequently employ timestomping to manipulate the metadata of malicious files, allowing them to blend in with legitimate system files or appear older than they are, thereby evading signature-based or heuristic detection systems. This technique involves modifying the creation, access, or modification timestamps of files. 

Defenders should focus on monitoring the modification of creation timestamps for executable files (such as .exe, .dll, .sys, .msi, .scr, .pif, and .lnk) within sensitive Windows directories, including `C:\Windows\System32`, `C:\ProgramData`, and user-specific startup folders. The detection logic provided identifies suspicious file creation time changes initiated by non-system processes, effectively distinguishing malicious activity from routine system operations or enterprise maintenance tasks that update binary metadata.

## Attack Chain

1. Attacker gains initial access or establishes persistence on the target Windows system.
2. Attacker downloads or stages a malicious executable or shortcut (.lnk) file.
3. Attacker executes a timestomping utility or utilizes Windows API calls (such as SetFileTime) to modify the file's creation timestamp.
4. The operating system updates the file metadata, triggering a Sysmon Event ID 2.
5. The attacker places or moves the modified file into a sensitive system or startup directory (e.g., `C:\Windows\System32` or `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`).
6. The modified file masquerades as a legitimate system binary or older, trusted file, bypassing simple temporal-based detection methods.
7. The attacker triggers the execution of the malicious file to maintain persistence or conduct further lateral movement.

## Impact

Successful timestomping undermines forensic timelines, makes malicious files appear benign, and assists in the long-term persistence of threats on a system. If undetected, attackers can maintain a foothold in the environment, facilitating ongoing data exfiltration, lateral movement, or ransomware deployment.

## Recommendation

1. Enable Sysmon Event ID 2 (File Creation Time Change) logging across all endpoints to capture the necessary telemetry.
2. Deploy the provided Sigma rule to your SIEM to monitor for unauthorized modifications to creation timestamps in sensitive directories.
3. Establish a baseline for automated administrative and update processes to tune the rule and minimize false positives.
4. Investigate any alerts generated for files located in startup directories as high-priority, as these are often indicators of persistence mechanisms.
