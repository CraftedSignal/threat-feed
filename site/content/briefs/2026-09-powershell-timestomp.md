---
title: Detection of PowerShell-Based Timestomping Activity
slug: 2026-09-powershell-timestomp
description: Adversaries utilize PowerShell commands to modify file system metadata, specifically targeting creation, access, and modification timestamps to evade detection and hinder forensic analysis.
date: "2026-09-03T13:43:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - anti-forensics
  - powershell
  - stealth
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times).
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_timestomp.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.006/T1070.006.md
  - https://www.offensive-security.com/metasploit-unleashed/timestomp/
rules:
  - title: Detect PowerShell File Metadata Modification (Timestomping)
    description: Detects the use of .NET PowerShell methods to modify file creation, access, or write timestamps, which is indicative of timestomping.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1070.006
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104) on all endpoints.
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into PowerShell-based timestomping.
  hunt_leads:
    - lead: Search PowerShell Script Block logs for .IO.File metadata manipulation patterns.
      technique_id: T1070.006
      data_needed:
        - Event ID 4104 (ScriptBlockText)
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Timestomping often uses documented .NET classes within scripts.
  mitigation_plan:
    - priority: medium_term
      action: Restrict PowerShell execution policy and enforce constrained language mode where possible.
      owner: IT Operations
      addresses: General PowerShell exploitation
      evidence: Limits impact of malicious script execution.
---

Timestomping is an anti-forensics technique used by adversaries to manipulate the metadata of files, including creation, access, and modification (MAC) timestamps. By altering these attributes to match legitimate system files or to predate the actual time of an attack, threat actors aim to disrupt incident response timelines and evade detection by security tools relying on time-based file activity. This activity is frequently observed in PowerShell scripts, which leverage the .NET framework's System.IO.File class to directly modify these attributes. Defenders must monitor PowerShell Script Block logging (Event ID 4104) to identify these modifications, as the behavior is common in post-exploitation scenarios where adversaries attempt to blend malicious tools into established file directories.

## Attack Chain

1. Attacker establishes an initial foothold on a Windows host using a malicious payload or script.
2. Attacker deploys a secondary implant or tool to the filesystem.
3. Attacker identifies the target file path on the local or network drive.
4. Attacker executes a PowerShell script block utilizing [IO.File]::SetLastWriteTime or similar .NET methods.
5. The file's metadata is updated, effectively hiding the actual modification time from standard file explorers and forensic tools.
6. Attacker proceeds with further post-exploitation activities such as privilege escalation or lateral movement.
7. Final objective is achieved, such as credential harvesting or exfiltration, with an obscured forensic trail.

## Impact

Successful timestomping impacts incident response investigations by creating inaccurate timelines of attacker activity. This complicates the identification of malicious file creation times, making it difficult for responders to correlate events with specific infection windows or C2 communication, potentially allowing attackers to maintain persistence undetected.

## Recommendation

Prioritize the implementation of PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to capture the commands executed by malicious scripts. Deploy the provided Sigma rule to your SIEM to alert on unauthorized metadata manipulation attempts.

- Enable PowerShell Script Block Logging (Event ID 4104) via Group Policy to ensure visibility into the commands used for file attribute modification.
- Deploy the following Sigma rule to detect the .NET file attribute modification methods commonly used in timestomping.
- Investigate any hits from this rule to differentiate between legitimate administrative maintenance and suspicious anti-forensics activity.
