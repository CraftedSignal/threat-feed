---
title: Suspicious PowerShell Execution from Temporary Directories
slug: 2026-09-powershell-temp-execution
description: Detection of potentially malicious PowerShell script execution originating from common temporary directory paths, often indicative of staged payload execution.
date: "2026-09-01T12:23:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - powershell
  - windows
  - suspicious-activity
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The detection rule identifies PowerShell script executions from temporary folder locations.
    confidence_band: high
rules:
  - title: Detect Suspicious PowerShell Execution from Temp
    description: Detects PowerShell execution from common user-writable temporary directories
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for execution from temp paths
      owner: Detection Engineering
      due: 72h
      evidence: Source provided Sigma rule for temp folder monitoring
---

Adversaries frequently utilize temporary directories (e.g., %TEMP%, %TMP%, or AppData\Local\Temp) to stage and execute malicious payloads. Because these directories are generally writable by standard users, they serve as ideal staging grounds for scripts and binaries dropped by initial access vectors. The execution of PowerShell scripts (`powershell.exe` or `pwsh.exe`) from these locations is a common TTP used to execute implants, download additional stages, or initiate post-exploitation commands. This brief highlights the need for visibility into command-line arguments when PowerShell processes are launched from non-standard or user-accessible temporary file paths. Defenders should prioritize monitoring these paths for unauthorized execution to disrupt the early stages of the post-compromise lifecycle.

## Impact

Successful execution of PowerShell scripts from temporary directories can lead to full host compromise, credential theft, and lateral movement. If left undetected, attackers can maintain persistence or exfiltrate sensitive data. This activity is frequently observed in malware droppers and sophisticated intrusion campaigns.

## Recommendation

- Deploy the Sigma rule below to monitor process creation events involving PowerShell execution from temporary directories.
- Tune the detection logic by creating allowlists for known-good administrative scripts or deployment agents (e.g., Chocolatey, EC2 launch agents) to reduce false positives.
- Enable Sysmon or Windows Event Log (Event ID 4688 with command line auditing) to ensure visibility into the full process command line.
