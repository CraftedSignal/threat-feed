---
title: Shell Execution via Elastic Endpoint on Linux
slug: 2026-07-elastic-endpoint-shell-execution
description: This brief details the detection of shell command execution initiated by the Elastic Endpoint agent on Linux systems, indicating potential post-exploitation activity such as remote access or command and control via misuse of the endpoint's response capabilities.
date: "2026-07-06T17:29:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - endpoint-security
  - command-and-control
  - defense-evasion
  - execution
  - detection-rule
vendors:
  - Elastic
  - SentinelOne
products:
  - Elastic Endpoint
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Tools
    evidence: This rule detects shell executions via Elastic Endpoint, which has a built-in response action console that can be used to execute shell commands on compromised systems, enabling remote access.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The rule detects command execution where the process.parent.executable is '/opt/Elastic/Endpoint/elastic-endpoint', implying the use of a legitimate system binary (the endpoint agent) to proxy malicious command execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The detection specifically targets process.name in ('bash', 'dash', 'sh', 'tcsh', 'csh', 'zsh', 'ksh', 'fish') and process.args in ('-c', '-cl', '-lc', '--command'), which are characteristic of Unix shell command execution.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_elastic_endpoint_shell_execution.toml
rules:
  - title: Detect Shell Execution via Elastic Endpoint
    description: Detects suspicious shell executions on Linux where the parent process is the Elastic Endpoint agent, indicating potential misuse of the agent's response capabilities for command and control.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1218
      - T1219
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This threat brief focuses on the detection of malicious shell execution activities initiated by the Elastic Endpoint agent on Linux systems. Attackers gaining control over an Elastic Endpoint agent could leverage its built-in response action console to execute arbitrary shell commands on compromised machines. This technique allows adversaries to establish remote access, execute further commands, or maintain persistence, often bypassing standard detection mechanisms by masquerading as legitimate endpoint management actions. The detection rule targets the spawning of common shell interpreters (such as `bash`, `sh`, `zsh`) as child processes of the `/opt/Elastic/Endpoint/elastic-endpoint` binary, specifically when invoked with command execution arguments like `-c` or `--command`. This behavior is a strong indicator of post-exploitation activity, where an adversary is actively controlling the system through the endpoint agent, making it critical for defenders to identify and respond to promptly.

## Attack Chain

This detection rule focuses on a post-exploitation phase where an attacker has already gained sufficient access to leverage the Elastic Endpoint agent.

1.  **Initial Compromise (Pre-requisite)**: An attacker gains initial access to a Linux system through various means (e.g., exploitation of a vulnerability, compromised credentials, or malicious payload).
2.  **Privilege Escalation / Lateral Movement (Pre-requisite)**: The attacker may escalate privileges or move laterally to a system where the Elastic Endpoint agent is running with sufficient permissions.
3.  **Abuse Elastic Endpoint Functionality**: The attacker interacts with the compromised Elastic Endpoint agent, potentially through its API or an exposed administrative interface, to instruct it to execute commands.
4.  **Shell Process Creation**: The `elastic-endpoint` process, acting on the attacker's commands, spawns a child process for a shell interpreter (e.g., `bash`, `sh`, `zsh`).
5.  **Command Execution**: The spawned shell executes arbitrary commands supplied by the attacker (e.g., `-c "whoami"`, `-lc "ls -la /tmp"`), leading to system reconnaissance, data exfiltration, or further malware deployment.
6.  **Command and Control / Impact**: The executed commands facilitate command and control, enable persistence, or contribute to the attacker's final objective, such as data exfiltration or system disruption.

## Impact

Successful exploitation of this technique provides attackers with a stealthy method to execute arbitrary commands on a compromised Linux host, using a trusted endpoint security agent as a proxy. This can lead to full system compromise, data theft, deployment of additional malware (e.g., ransomware, cryptominers), or establishment of long-term persistence within the environment. Since the activity originates from a legitimate security product's process, it can evade less sophisticated monitoring solutions, making detection crucial. The potential for a wide range of follow-on activities means the impact can range from minor data exposure to complete business disruption.

## Recommendation

*   Deploy the Sigma rule "Detect Shell Execution via Elastic Endpoint" to your SIEM and tune for your Linux environment.
*   Ensure that Elastic Defend and Elastic Endpoint are configured for comprehensive logging of process creation events on Linux systems, as specified in the rule's `logsource`.
*   Review access controls and configurations for the Elastic Endpoint agent and its management interfaces to prevent unauthorized command execution capabilities.
*   Investigate any alerts triggered by the rule, paying close attention to the `CommandLine` arguments and the context of the `elastic-endpoint` process.
