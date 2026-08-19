---
title: Detection of Malicious Executables and Scripts in Temporary Directories
slug: 2026-08-temp-file-creation
description: Adversaries frequently utilize temporary Windows directories as staging areas to drop and execute malicious payloads, bypass detection, and maintain persistence.
date: "2026-08-19T22:27:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1036
    technique_name: Masquerading
    evidence: Adversaries often use these paths to evade detection and maintain persistence.
    confidence_band: high
rules:
  - title: Detect Executables or Scripts Created in Temporary Paths
    description: Detects the creation of executables, DLLs, or scripts within common Windows temporary directories, a technique frequently used by attackers to stage payloads.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1036
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable Sysmon FileCreate monitoring on all Windows endpoints
      owner: IT Operations
      due: 48h
      evidence: Source requirement for Sysmon EventID 11
  hunt_leads:
    - lead: Search for unsigned binaries created in AppData\Local\Temp
      technique_id: T1036
      data_needed:
        - Sysmon Event ID 11
        - Process signature information
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: General threat actor staging patterns
---

Adversaries often exploit temporary system directories, such as \Temp\, \Windows\Temp\, and \AppData\Local\Temp\, to facilitate the execution of malicious payloads. Because these directories are intended for transient data, they are frequently used as staging areas to hide executables, DLLs, and scripts used for persistence or lateral movement. Threat actors ranging from ransomware operators like LockBit and Rhysida to commodity malware such as Remcos and AsyncRAT use these paths to drop binaries and scripts that avoid more strictly monitored application directories. Detection is crucial for identifying unauthorized code execution, privilege escalation attempts, and persistent backdoor installations within an environment.

## Attack Chain

1. An attacker gains initial access, often via phishing or exploited services.
2. The attacker uses built-in tools or custom droppers to download or move malicious binaries to a temporary directory.
3. A malicious file (e.g., .exe, .ps1, .vbs) is written to a temporary path (e.g., \AppData\Local\Temp\).
4. The attacker sets the file attribute or modifies execution permissions if necessary.
5. The attacker executes the payload, often via command-line invocation or scheduled task.
6. The payload performs its objective, such as credential theft, data destruction, or establishing C2.

## Impact

Successful exploitation of this technique can lead to full system compromise, ransomware deployment, data exfiltration, or the establishment of persistent backdoors. These activities have been observed across a wide range of sectors, targeting both critical infrastructure and general enterprise environments, with significant potential for operational disruption and financial loss.

## Recommendation

Deploy detection rules to monitor for file creation events within temporary directories and cross-reference these with process execution telemetry. 
- Enable Sysmon Event ID 11 (FileCreate) to log file system activity in all temporary directories.
- Integrate endpoint logs into a SIEM using a normalized data model (e.g., CIM) to enable monitoring of file creation events.
- Investigate any occurrences where non-standard binaries or scripts are created in temporary paths, particularly when associated with suspicious parent processes.
- Use the provided Sigma rule to alert on unauthorized file creations and tune out legitimate temp file activity based on known-good baseline behavior.
