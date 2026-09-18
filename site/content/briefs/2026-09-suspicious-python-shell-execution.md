---
title: Suspicious Python Shell Command Execution
slug: 2026-09-suspicious-python-shell-execution
description: This detection logic identifies potentially malicious activity where a Python process rapidly spawns multiple shell commands via '-c' arguments for host profiling, discovery, or lateral movement.
date: "2026-09-18T19:17:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - script-based-execution
  - python
  - linux
  - macos
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers may use Python to execute shell commands to gain access to the system or to perform other malicious activities.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/execution_suspicious_python_command_execution.toml
rules:
  - title: Detect Suspicious Python Shell Command Execution
    description: Detects Python processes rapidly spawning multiple shell commands, indicating potential malicious host profiling and discovery.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rules for Python-spawned shell processes
      owner: Detection Engineering
      due: 72h
      evidence: Rule definition in brief.
  hunt_leads:
    - lead: Identify all Python processes spawning multiple child shell processes
      technique_id: T1059.006
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Rule detection logic.
---

This detection rule focuses on identifying suspicious activity on Linux and macOS systems where a Python interpreter initiates a rapid sequence of shell commands. Attackers frequently leverage Python to execute shell commands (e.g., `sh -c`) as part of a post-exploitation workflow. This allows them to profile the compromised host, locate sensitive data, pull down additional malicious payloads via `curl` or `wget`, and facilitate lateral movement or persistence. 

The core indicator is the rapid execution of at least five distinct command lines containing at least four unique command patterns (such as environment enumeration, discovery utilities, or network tools) within a single one-minute window. This behavior is indicative of automated scripting used by a backdoor rather than standard administrative or application-level behavior. Defenders should focus on Python-led process trees that diverge from approved deployment or maintenance workflows.

## Attack Chain

1. An attacker gains initial execution on a Linux or macOS host, often through a web shell or a malicious script.
2. The attacker executes a Python-based backdoor or script to facilitate hands-on-keyboard activity.
3. The Python process begins profiling the host environment by spawning child shell processes (e.g., `bash`, `sh`, `zsh`).
4. The shell child processes execute discovery commands such as `whoami`, `uname`, and `hostname` via `sh -c`.
5. The script iterates through system configuration or environment variables using commands like `env` or `find`.
6. The attacker uses the shell child processes to invoke `curl` or `wget` to retrieve follow-on payloads from external C2 infrastructure.
7. The script attempts to access sensitive files or modify system configurations to achieve persistence.
8. Final objective is achieved, such as credential theft, data exfiltration, or establishing a recurring command-and-control connection.

## Impact

Successful exploitation allows attackers to gain full visibility into the host environment, extract credentials, and move laterally across the network. If left undetected, this activity leads to significant data breaches, unauthorized access to sensitive application secrets, and potential long-term persistence within the organization's infrastructure.

## Recommendation

Prioritize the implementation of process-creation telemetry to monitor for anomalous shell command patterns initiated by Python.
- Deploy the provided Sigma rule logic to your SIEM to monitor for Python processes spawning high volumes of shell children.
- Implement egress filtering to block unauthorized connections from Python or shell interpreters to known untrusted infrastructure.
- Audit all Python execution paths in temporary directories and restrict the ability of service accounts to spawn shell interpreters.
- Investigate any occurrences flagged by the detection logic to confirm whether they originate from approved administrative scripts or unauthorized malicious payloads.
