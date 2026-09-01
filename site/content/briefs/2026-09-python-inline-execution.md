---
title: Python Inline Command Execution Technique
slug: 2026-09-python-inline-execution
description: Adversaries utilize the Python '-c' flag to execute arbitrary code or payloads directly from the command line, bypassing file-based execution triggers.
date: "2026-09-01T12:23:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - execution
  - scripting
  - python
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects execution of python using the -c flag
    confidence_band: high
rules:
  - title: Detect Python Inline Command Execution
    description: Detects execution of python using the '-c' flag, which can be used to launch a reverse shell or execute live python code.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
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
    - action: Deploy the Sigma detection rule to the SIEM
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for ' -c' in command line logs for python processes
      technique_id: T1059
      data_needed:
        - process_creation
      priority: medium
      confidence: medium
      disposition: convert_to_detection
---

The Python interpreter supports the '-c' command-line flag, which allows users to pass a string as a command to be executed by the interpreter. While this is a standard feature for development and scripting, it is frequently abused by attackers as a living-off-the-land technique to execute malicious logic, such as reverse shells, without dropping scripts to the disk. Defenders often see this activity during the exploitation phase of an attack, where a compromised application invokes a system-level interpreter to establish network persistence or perform further system enumeration. Because the Python binary itself is often expected in many administrative or development environments, detection requires distinguishing between legitimate package management or IDE-driven execution and unauthorized command execution. This threat is particularly prevalent in environments where Python is installed as a prerequisite for various developer tools or server applications.

## Impact

Successful execution of malicious inline Python code can lead to complete host compromise, including the establishment of persistent reverse shells, credential theft, and unauthorized data exfiltration. This technique allows attackers to execute complex logic using the full capabilities of the Python standard library while minimizing their forensic footprint by avoiding the creation of persistent script files.

## Recommendation

Deploy the provided Sigma rule to monitor process creation events for Python binaries invoking the '-c' flag. Tune the detection by baseline-filtering legitimate software installers, IDEs like VS Code, and internal deployment scripts identified in the false-positive section of the detection metadata. Prioritize alerts where the parent process is a web server, document processor, or other internet-facing application.
