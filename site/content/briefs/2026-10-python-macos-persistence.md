---
title: Python-Based Persistence via macOS Launch Agents and Daemons
slug: 2026-10-python-macos-persistence
description: Attackers are leveraging Python scripts, compromised dependencies, and insecure model deserialization to establish persistence on macOS by creating malicious LaunchAgent and LaunchDaemon plist files.
date: "2026-10-01T20:15:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - macos
  - python
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Attackers who achieve Python code execution can drop plist files to establish persistence on the compromised host.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Attackers who achieve Python code execution can drop plist files to establish persistence on the compromised host.
    confidence_band: high
references:
  - https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/
  - https://github.com/trailofbits/fickling
rules:
  - title: Detect First Time Python Created a LaunchAgent or LaunchDaemon
    description: Detects the first time a Python process creates or modifies a LaunchAgent or LaunchDaemon plist file on a host.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.001
      - T1543.004
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma-compatible rule provided to the endpoint monitoring system.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 25368123-b7b8-4344-9fd4-df28051b4c6e
  mitigation_plan:
    - priority: short_term
      action: Review and restrict write permissions for LaunchAgent/LaunchDaemon directories on sensitive macOS workstations.
      owner: IT Operations
      evidence: General macOS hardening practices
---

Adversaries are increasingly using Python-based execution vectors to establish long-term access on macOS endpoints. By exploiting malicious scripts, vulnerable third-party dependencies, or insecure deserialization routines in machine learning models (such as pickle or PyTorch `__reduce__`), attackers can force a Python process to write configuration files into the system's LaunchAgent or LaunchDaemon directories. 

These plist files configure the operating system to automatically launch malicious payloads upon user login or system boot. Because legitimate administrative tools rarely use Python to create these persistence mechanisms, the first-time occurrence of a Python process performing these file operations is a high-fidelity indicator of potential compromise. This technique is particularly concerning in development or data science environments where frequent loading of untrusted model files or dependencies occurs, as it allows attackers to bypass traditional detection by operating within the context of trusted application frameworks.

## Impact

Successful exploitation results in unauthorized persistent access to macOS systems. This allows attackers to maintain command-and-control communication, exfiltrate sensitive data, or deploy further malicious payloads across reboots. This technique primarily impacts organizations using macOS for research, machine learning, or software development, where the use of third-party packages and pre-trained model files is prevalent.

## Recommendation

Prioritize the identification of unauthorized persistence mechanisms created by Python processes.

* Deploy detection logic to flag the creation of LaunchAgent and LaunchDaemon files by `python*` processes, specifically monitoring for the first occurrence on a per-host basis.
* Audit all Python-based system management tools (e.g., Ansible, SaltStack) in your environment to create allowlists for legitimate automation workflows.
* Enforce security scanning for model files (e.g., using tools like Fickling) to detect malicious pickle payloads before execution.
* If a suspicious plist is identified, use `launchctl unload` to immediately terminate the persistent process and isolate the host for forensic analysis.
