---
title: Suspicious mkfifo Execution on Linux
slug: 2024-01-suspicious-mkfifo-execution
description: This brief covers the suspicious execution of commands following the use of 'mkfifo' on Linux systems, often indicating malicious activity such as establishing named pipes for command and control or data exfiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mkfifo
  - named_pipe
  - linux
  - command_execution
  - lateral_movement
products:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1571
    technique_name: Non-Standard Port
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_suspicious_mkfifo_execution.toml
rules:
  - title: Suspicious Mkfifo Followed by Command Execution
    description: Detects suspicious execution of mkfifo followed by command execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Mkfifo and Netcat Use
    description: Detects suspicious use of mkfifo in conjunction with netcat for potential command and control or data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1571
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This threat brief addresses suspicious activities on Linux systems involving the `mkfifo` command. While `mkfifo` itself is a legitimate utility for creating named pipes, its use followed by command execution can indicate malicious intent. Attackers may use named pipes for inter-process communication, command and control (C2), or data exfiltration. This activity is often seen in post-exploitation scenarios. The use of `mkfifo` in conjunction with other commands such as `nc`, `bash`, or scripting languages like Python warrants close examination. The scope of this brief focuses on Linux-based systems and the detection of command sequences indicating potential abuse of `mkfifo`. Defenders should monitor for unusual process chains involving `mkfifo` and subsequent command executions.

## Attack Chain

1.  The attacker gains initial access to a Linux system through an exploit or compromised credentials.
2.  The attacker uses `mkfifo /tmp/named_pipe` to create a named pipe in the /tmp directory.
3.  The attacker uses netcat to listen on a port and write output to the named pipe: `nc -l -p 1337 > /tmp/named_pipe`.
4.  In a separate process, the attacker executes a command and redirects the output to the named pipe: `ls -la > /tmp/named_pipe`.
5.  The netcat process receives the output of the `ls -la` command and forwards it to the attacker's C2 server.
6.  The attacker uses `rm /tmp/named_pipe` to remove the named pipe, cleaning up evidence.
7.  The attacker may repeat steps 2-5 to execute further commands and exfiltrate data.

## Impact

Successful exploitation can lead to unauthorized access, data exfiltration, and command execution on the compromised Linux system. The severity of the impact depends on the privileges of the compromised user and the sensitivity of the data accessible on the system. This technique can be used to establish covert communication channels for lateral movement and persistence within the network.

## Recommendation

*   Deploy the provided Sigma rule to detect suspicious process executions involving `mkfifo` followed by network activity or command execution (see "Suspicious Mkfifo Followed by Command Execution" and "Suspicious Mkfifo and Netcat Use" rules).
*   Monitor process creation logs for the execution of `mkfifo` command, focusing on parent processes and subsequent child processes.
*   Investigate any instances of `mkfifo` usage where the created named pipe is used for network communication or data redirection.
*   Enable process monitoring with command line auditing to capture the full context of `mkfifo` executions and related commands.
