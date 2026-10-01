---
title: Detection of First-Time Python-Initiated Shell Execution on macOS
slug: 2026-10-python-shell-spawn
description: This detection monitors for the first time a Python process spawns a shell on a macOS host, a common indicator of post-exploitation activity such as malicious model deserialization or compromised dependency execution.
date: "2026-10-01T20:15:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - macos
  - execution
  - python
  - command-injection
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries frequently utilize Python for post-exploitation tasks, such as deserializing malicious model files or executing compromised dependencies, to launch interactive shells.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries frequently utilize Python for post-exploitation tasks, such as deserializing malicious model files or executing compromised dependencies, to launch interactive shells.
    confidence_band: high
references:
  - https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/
  - https://github.com/trailofbits/fickling
  - https://5stars217.github.io/2024-03-04-what-enables-malicious-models/
rules:
  - title: Detect First Time Python Spawned a Shell on macOS
    description: Detects the first time a Python process spawns a shell with the -c flag on a macOS host, excluding common package management and data science tools.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1059.006
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the provided Sigma rule to production to baseline Python shell activity.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 92a36c98-b24a-4bf7-aac7-1eac71fa39cf
  hunt_leads:
    - lead: Search historical logs for any Python process spawning a shell in the last 30 days to identify potential existing persistence.
      technique_id: T1059
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Rule metadata indicates potential for detecting post-exploitation persistence.
---

This detection focuses on identifying anomalous behavior where a Python process initiates an interactive or command-line shell session on macOS. Adversaries frequently leverage Python-based execution for malicious purposes, including the deserialization of malicious machine learning models (e.g., using `pickle` or PyTorch `__reduce__`) and the execution of backdoored software dependencies. 

Since legitimate Python applications rarely require spawning shell commands (e.g., `bash`, `zsh`) via the `-c` flag, the first occurrence of this behavior on a host is a significant signal of potential compromise. This approach is intended to distinguish between established, baseline Python workflows and novel execution patterns. The detection logic excludes common administrative tools such as `pip`, `conda`, `brew`, and `jupyter` to minimize noise, making it suitable for identifying unauthorized post-exploitation reconnaissance, persistence, or reverse shell activity.

## Impact

Successful exploitation allows attackers to execute arbitrary system commands with the privileges of the Python process. Observed techniques often facilitate credential theft, lateral movement, persistent access, and data exfiltration. If left undetected, this activity can lead to a full system compromise, especially within environments utilizing untrusted machine learning model files or external packages.

## Recommendation

Prioritized actions for detection engineering teams:

- Deploy the Sigma rule below to your macOS monitoring environment to identify anomalous shell spawning.
- Establish a baseline for normal Python execution behavior to tune the "first occurrence" detection logic.
- Implement environment-wide security controls for model loading, specifically enforcing `weights_only=True` for all PyTorch model deployments.
- Review and restrict the use of Python environments that allow arbitrary command execution in sensitive production segments.
- Update SIEM dashboards to alert on the first instance of process-parent-child execution chains where Python spawns `/bin/bash` or `/bin/zsh`.
