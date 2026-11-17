---
brief_id: brief-2026-11-17-macos-python-shell
event_id: brief-2026-11-17-macos-python-shell
revision: 1
activity_at: "2026-11-17T14:57:30Z"
title: 'MacOS: First occurrence of shell spawning via Python'
slug: 2026-11-macos-python-shell
description: This detection rule identifies the first instance of a Python process spawning a shell with the -c flag on a macOS host, a behavior frequently associated with malicious script execution, compromised dependencies, or model file deserialization.
date: "2026-11-17T14:57:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
tags:
  - execution
  - macos
  - python
  - threat-detection
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: Attackers who achieve Python code execution — whether through malicious scripts, compromised dependencies, or model file deserialization (e.g., pickle/PyTorch __reduce__) — often spawn shell processes to perform reconnaissance, credential theft, persistence, or reverse shell activity.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.006
    subtechnique_name: Python
    evidence: Attackers who achieve Python code execution — whether through malicious scripts, compromised dependencies, or model file deserialization (e.g., pickle/PyTorch __reduce__) — often spawn shell processes to perform reconnaissance, credential theft, persistence, or reverse shell activity.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/execution_python_shell_spawn_first_occurrence.toml
  - https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/
  - https://github.com/trailofbits/fickling
  - https://5stars217.github.io/2024-03-04-what-enables-malicious-models/
rules:
  - title: First Time Python Spawned a Shell on Host
    description: Detects the first time a Python process spawns a shell on a macOS host using the -c flag, excluding known package managers and build tools.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1059.006
    data_sources:
      - process_creation
      - macos
rules_count: 1
---

## Overview
This rule detects the first time a Python process spawns a shell on a given macOS host. Attackers who achieve Python code execution - whether through malicious scripts, compromised dependencies, or model file deserialization (e.g., pickle/PyTorch __reduce__) - often spawn shell processes to perform reconnaissance, credential theft, persistence, or reverse shell activity. Since legitimate Python workflows rarely shell out with the -c flag, a first occurrence on a host is a strong signal of potential compromise.

## Attack Chain
Python code execution (malicious scripts, dependencies, or deserialization) is followed by the execution of a shell process via the -c flag for post-exploitation activities.

## Impact
Exploitation may lead to unauthorized command execution, reconnaissance, credential theft, persistence, or reverse shell activity. The impact is limited by the privileges of the executing Python process.

## Recommendation
- Monitor for the first occurrence of Python spawning a shell using the -c flag.
- Investigate the parent process command line to identify the source of the Python execution.
- Inspect the shell command arguments for malicious intent.
- Consider enforcing weights_only=True for PyTorch model loading.
