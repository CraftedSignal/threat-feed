---
title: OS Command Injection Vulnerability in MONAI
slug: 2026-08-monai-command-injection
description: The MONAI library contains a command injection vulnerability where unsanitized configuration values in YAML files are passed to shell execution, allowing arbitrary code execution.
date: "2026-08-18T20:57:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - command-injection
  - python
  - monai
vendors:
  - MONAI
products:
  - MONAI (< 1.6.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'Since this string is passed to subprocess with shell=True, shell metacharacters (e.g., Windows: & / Linux: ;) are interpreted.'
    confidence_band: high
rules:
  - title: Detect Python Spawning Shell Commands via subprocess
    description: Detects Python processes spawning shells or executing commands that contain shell metacharacters, a common indicator of command injection attempts.
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
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade MONAI library to 1.6.0
      owner: IT Operations
      due: 48h
      evidence: 'Affected Packages: pip/MONAI (vulnerable: < 1.6.0)'
  mitigation_plan:
    - priority: immediate
      action: Review and sanitize YAML input files used by MONAI workloads
      owner: IT Operations
      addresses: CWE-78 (OS Command Injection)
      evidence: This library concatenates user-controlled values ... without quoting or validation.
---

MONAI versions prior to 1.6.0 are susceptible to OS command injection due to insecure handling of user-controlled configuration parameters within YAML files. Specifically, parameters such as 'dataset_name_or_id' or various CLI arguments are concatenated into strings and processed by the `subprocess` module with `shell=True`. Because this input is not properly quoted or validated, an attacker can inject shell metacharacters - such as '&' on Windows or ';' on Linux - to escape the intended command context and execute arbitrary system instructions. This vulnerability (CWE-78) is triggered whenever a victim loads a malicious YAML configuration file into a training or validation pipeline. Defenders should prioritize updating the MONAI package to version 1.6.0 or later to mitigate the risk of remote code execution on systems running medical imaging training tasks.

## Impact

Successful exploitation allows an attacker to execute arbitrary commands with the privileges of the user running the MONAI training or validation scripts. This can lead to full system compromise, exfiltration of sensitive medical imaging datasets, or the deployment of persistent malware on workstations and servers used for research and clinical analysis.

## Recommendation

* Update the MONAI package to version 1.6.0 or higher across all development and production environments.
* Implement strict validation and input sanitization for any YAML configuration files used in machine learning pipelines.
* Run training jobs under restricted service accounts with minimal filesystem and network permissions to limit the impact of potential command execution.
* Monitor process creation logs for unusual child processes spawned by python.exe or python3, particularly those involving shell command separators.
