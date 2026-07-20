---
title: Linux Interpreter Downloads and Pipes Payload for Execution
slug: 2026-07-payload-piped-to-interpreter
description: This detection rule targets a Linux defense evasion technique where an interpreter downloads a malicious payload from an external address and immediately pipes its content into another interpreter for in-memory execution, allowing attackers to establish persistence, exfiltrate data, or run stagers without writing files to disk.
date: "2026-07-20T13:16:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - execution
  - defense-evasion
  - command-and-control
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule detects when a payload is downloaded by an interpreter, and piped to an interpreter. Attackers may use this technique to download and execute payloads for various malicious purposes.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: for example by having Python fetch a remote shell script with urllib and pipe the response into `sh` or `bash` to run a stager in memory.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This rule flags a Linux interpreter that reaches out to an external address... to download and execute payloads
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_payload_downloaded_by_interpreter_and_piped_to_interpreter.toml
rules:
  - title: Detect Linux Interpreter Receiving Piped Input
    description: Detects Linux interpreters launched with arguments indicating they are receiving input via a pipe, a common technique for executing downloaded payloads directly in memory for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This brief describes a detection rule focused on a Linux execution and defense evasion technique where attackers leverage native interpreters to download and execute payloads without writing them to disk. The method involves an interpreter, such as Python or a shell, initiating an outbound network connection to fetch a malicious script or binary. The downloaded content is then directly streamed (piped) as input to another interpreter, like `sh` or `bash`, which executes it in memory. This technique allows adversaries to bypass file-based defenses, maintain a low footprint, and blend with legitimate administrative activities. Attackers utilize this for various malicious purposes including establishing persistence, exfiltrating sensitive data, or executing in-memory stagers for further compromise, making it a critical behavior to detect on Linux endpoints.

## Attack Chain

1. An initial interpreter process (e.g., `python`, `bash`, `perl`, `curl`, `wget` implicitly via a shell command) establishes an outbound network connection to a remote, external IP address.
2. The interpreter downloads a malicious payload, which can be a script or raw binary data.
3. Instead of saving the payload to disk, its output stream is immediately piped as standard input to a second interpreter process (e.g., `sh`, `bash`, `python`).
4. The second interpreter executes the received content directly in memory, often indicated by a command line argument like `sh -` or `bash -`.
5. This in-memory execution often involves a stager script designed to download subsequent stages of malware or establish initial access.
6. The ultimately executed payload can then perform actions such as establishing persistence, escalating privileges, conducting lateral movement, or exfiltrating data.

## Impact

Successful exploitation using this technique can lead to significant compromise of Linux systems. Attackers can gain persistent access to compromised hosts, escalate privileges, exfiltrate sensitive data, and pivot to other systems within the network. Since the payloads are executed in memory, forensic analysis can be more challenging, potentially delaying detection and response. The impact can range from data breaches and service disruption to complete system control, depending on the attacker's objectives and the nature of the executed payload.

## Recommendation

* Deploy the Sigma rule provided in this brief to your SIEM and tune for your environment to detect interpreters receiving piped input.
* Configure Elastic Defend integration to collect `process_creation` and `network_connection` logs from all Linux endpoints, as required by the detection rule.
* Monitor outbound network connections from interpreters using `network_connection` logs, especially to unusual or untrusted external destinations.
* Audit and reconstruct the full process lineage and execution context from `process_creation` logs for any alerts generated by the rule to distinguish legitimate automation from malicious activity.
* Implement strong egress filtering to restrict direct internet access from interpreters and server applications, allowing connections only to approved package mirrors and script repositories.
