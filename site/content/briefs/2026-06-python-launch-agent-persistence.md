---
title: First Time Python Process Creates macOS Launch Agent or Daemon
slug: 2026-06-python-launch-agent-persistence
description: This rule detects the initial creation or modification of a macOS LaunchAgent or LaunchDaemon plist file by a Python process, a common persistence technique employed by attackers using malicious scripts, compromised dependencies, or model file deserialization.
date: "2026-04-08T21:12:54Z"
severities:
  - medium
tags:
  - persistence
  - macos
  - python
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/persistence_python_launch_agent_or_daemon_creation_first_occurrence.toml
  - https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/
  - https://github.com/trailofbits/fickling
rules:
  - title: Detect Python Launch Agent/Daemon Creation
    description: Detects when a Python process creates or modifies a LaunchAgent or LaunchDaemon plist file, indicating potential persistence establishment.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.001
      - T1543.004
    data_sources:
      - file_event
      - macos
  - title: Detect Modified LaunchAgent or LaunchDaemon by Python
    description: Detects modifications to LaunchAgent or LaunchDaemon plist files by python processes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.001
      - T1543.004
    data_sources:
      - file_event
      - macos
rules_count: 2
---

This threat brief highlights the malicious use of Python to establish persistence on macOS systems. Attackers can achieve Python code execution through various means, including malicious scripts, compromised dependencies, or even model file deserialization vulnerabilities (such as pickle or PyTorch `__reduce__` exploits). Once code execution is achieved, attackers can drop plist files into LaunchAgent or LaunchDaemon directories, ensuring their payload survives reboots and user logouts. This…
