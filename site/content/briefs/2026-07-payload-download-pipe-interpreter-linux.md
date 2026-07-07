---
title: Detecting Linux Payload Downloaded and Piped to Interpreter
slug: 2026-07-payload-download-pipe-interpreter-linux
description: This brief details a common Linux technique where attackers use scripting interpreters to download malicious payloads from external sources and immediately pipe them into another interpreter for execution, often for purposes like persistence or data exfiltration.
date: "2026-07-06T17:39:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - defense-evasion
  - command-and-control
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule detects when a payload is downloaded by an interpreter, and piped to an interpreter. Attackers may use this technique to download and execute payloads.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This rule detects when a payload is downloaded by an interpreter... Attackers may use this technique to download and execute payloads.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/execution_payload_downloaded_by_interpreter_and_piped_to_interpreter.toml
rules:
  - title: Detect Linux Payload Downloaded and Piped to Interpreter
    description: Detects common Linux interpreters executing commands that involve downloading content via curl/wget and piping it directly for execution, a common defense evasion technique.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - defense_evasion
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1071
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This threat describes a stealthy method employed by adversaries on Linux systems to execute arbitrary code. It involves an initial interpreter (such as a shell, Python, Perl, or Node.js) making an outbound network connection to download a malicious payload. Crucially, this payload is not written to disk but is directly piped as input into a second interpreter (often another shell instance, or a scripting language runtime) for immediate execution. This technique helps attackers evade detection by bypassing file-based security controls and minimizing forensic artifacts. While this brief does not detail a specific campaign, the technique is widely used across various threat groups for initial access, backdoor deployment, or data exfiltration.

## Attack Chain

This brief focuses on a specific execution technique rather than a multi-stage campaign:

1.  **Initial Compromise (Implied):** An attacker gains initial access to a Linux system through various means (e.g., exploitation of a vulnerable service, compromised credentials, or successful phishing).
2.  **Network Connection by Interpreter:** A command-line interpreter (e.g., `bash`, `python`, `curl`) is executed to initiate an outbound network connection to a malicious command-and-control (C2) server.
3.  **Payload Download:** The C2 server delivers a malicious script or binary payload over the established network connection.
4.  **In-Memory Piping:** Instead of writing the downloaded payload to a file, the output stream from the download utility is immediately piped (`|`) into another command-line interpreter.
5.  **Interpreter Execution:** The second interpreter (e.g., `sh`, `bash`, `python`) receives the malicious payload directly as its standard input and executes it in memory.
6.  **Malicious Activity:** The executed payload then performs its intended malicious function, such as establishing persistence, exfiltrating data, or launching further attacks.

## Impact

Successful execution of payloads using this technique can lead to significant compromise of Linux systems. Because the payload is executed in memory without touching disk, it complicates traditional endpoint detection and incident response efforts. Consequences include system backdooring, complete system takeover, deployment of ransomware, data theft, and lateral movement within the network. This method is particularly effective against environments with weak network egress filtering and endpoint visibility into process command lines.

## Recommendation

*   Deploy the Sigma rule provided in this brief to your SIEM/EDR and tune for your Linux environment.
*   Ensure comprehensive `process_creation` logging is enabled for all Linux endpoints to capture command-line arguments.
*   Implement robust egress filtering at the network perimeter to restrict outbound connections from internal systems to known malicious IP addresses or unexpected ports and protocols, especially for common interpreter binaries.
*   Regularly audit the `command_line` arguments of interpreters like `bash`, `sh`, `python`, and `perl` for suspicious download and pipe patterns, as detected by the rule above.
