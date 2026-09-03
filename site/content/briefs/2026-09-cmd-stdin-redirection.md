---
title: Detection of CMD.EXE Standard Input Redirection
slug: 2026-09-cmd-stdin-redirection
description: This rule identifies the use of the '<' operator with cmd.exe to read content from files or streams, a technique often used by attackers to bypass execution policy restrictions or bypass basic file-based detection.
date: "2026-09-03T13:45:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - command-and-control
  - windows
  - living-off-the-land
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The detection focuses on T1059.003 usage of redirection operators for command execution.
    confidence_band: high
rules:
  - title: Detect Cmd.exe Standard Input Redirection
    description: Detects the use of the '<' operator with cmd.exe to read content from files, a common technique for command obfuscation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for cmd.exe stdin redirection
      owner: Detection Engineering
      due: 72h
      evidence: Source rule requirement
  hunt_leads:
    - lead: Search for historical cmd.exe command lines containing the '<' character to establish baselines
      technique_id: T1059.003
      data_needed:
        - Process creation events
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Standard practice for initial detection deployment
---

Standard input (stdin) redirection via the '<' operator in cmd.exe is a command-line execution pattern used to feed file contents into a process. While often used for benign batch processing, it is frequently leveraged by threat actors to execute commands from hidden or non-executable files, thereby evading file-based signature detection or simple command-line monitoring. Defenders should monitor for this pattern to identify suspicious batch script execution or command injection attempts that rely on redirected input.

## Impact

Successful abuse of stdin redirection allows attackers to execute arbitrary code or scripts from files that may not be directly called by traditional execution commands. This technique is often seen as a secondary stage in lateral movement or persistence, helping to obfuscate the origin of executed code from standard process telemetry.

## Recommendation

Deploy the provided Sigma rule to identify command-line activity utilizing input redirection. Analysts should investigate instances where cmd.exe reads unexpected files or uses input redirection in conjunction with uncommon parent processes. Ensure process-creation logs (e.g., Sysmon Event ID 1) are enabled to capture full CommandLines.
