---
title: Abuse of osascript to Invoke Interactive Bash Shells on macOS
slug: 2026-09-macos-osascript-interactive-shell
description: Adversaries may abuse the macOS osascript utility to execute interactive shell commands for persistence or post-exploitation activities by invoking bash with interactive flags.
date: "2026-09-21T19:09:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - macos
  - post-exploitation
  - execution
  - command-and-control
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries may abuse osascript and AppleScript's shell execution capabilities to launch interactive shells.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1059/002/
  - https://attack.mitre.org/techniques/T1059/004/
  - https://redcanary.com/threat-detection-report/techniques/applescript/
  - https://www.loobins.io/binaries/osascript/
rules:
  - title: Detect MacOS Osascript Executing Interactive Shell
    description: Detects the macOS osascript utility being used to launch an interactive Bash shell, which is indicative of potential post-exploitation activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.002
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Implement process creation monitoring on macOS endpoints.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic guidance.
  hunt_leads:
    - lead: Search for all instances of osascript spawning bash or zsh in historic telemetry.
      technique_id: T1059.002
      data_needed:
        - Process creation events
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies this as a post-exploitation anomaly.
---

Adversaries targeting macOS systems may leverage the built-in osascript utility to execute AppleScript commands that invoke secondary processes, specifically interactive Bash shells. By passing bash commands with the "-i" flag to osascript, an attacker can maintain an interactive session for remote command execution, credential harvesting, or further lateral movement. This technique is often used during the post-exploitation phase to bypass standard execution restrictions or to hide malicious activity within the context of legitimate scripting environments. Defenders must monitor for osascript invocations that spawn shells, as this behavior deviates from typical system management utility usage.

## Attack Chain

1. An attacker gains initial access to a macOS system via spearphishing or exploit.
2. The attacker identifies the target binary, osascript, which is a native tool used to execute AppleScript.
3. The attacker crafts a payload that executes a shell command via osascript.
4. The command line includes the arguments "bash" and "-i", forcing an interactive session.
5. The osascript process is executed by the system or user context.
6. A bash process is spawned as a child of the osascript utility.
7. The attacker interacts with the shell to execute arbitrary commands or download additional tools.

## Impact

Successful exploitation allows for persistent unauthorized access to the host, sensitive data exfiltration, and the ability to execute further malicious code with the permissions of the compromised user or process.

## Recommendation

1. Deploy the Sigma rule below to monitor for suspicious process-creation events involving osascript and interactive shells.
2. Monitor osquery results specifically for process trees where osascript is the parent or initiator of shell-related processes (bash, zsh).
3. Establish a baseline for administrative and MDM-related osascript usage to reduce noise and identify legitimate automation workflows.
