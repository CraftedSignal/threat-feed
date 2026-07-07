---
title: 'Linux C2 Agent Activity: Suspicious Network Connection and File Creation'
slug: 2026-07-network-connection-file-creation
description: Threat actors leverage C2 agents like Poseidon and Athena, operating from suspicious Linux writable directories, to establish network connections with C2 frameworks such as Mythic, subsequently creating files to stage further malicious activities.
date: "2026-07-06T14:25:12Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - linux
  - command-and-control
  - execution
  - malware
  - c2
  - threat-detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The agent polls the C2 for commands through a web request
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: after which the command gets executed.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_netcon_file_creation.toml
rules:
  - title: Linux Suspicious Outbound Network from Writable Directory
    description: Detects outbound network connections originating from processes running in commonly writable and suspicious directories (e.g., /tmp, /dev/shm) on Linux systems, which is characteristic of C2 agents. Correlate with file creation events for higher fidelity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071
      - T1071.001
    data_sources:
      - network_connection
      - linux
  - title: Linux Suspicious File Creation by Process in Writable Directory
    description: Detects file creation events by processes running from commonly writable and suspicious directories (e.g., /tmp, /dev/shm) on Linux systems, indicative of C2 agents staging payloads or scripts. Correlate with outbound network connections for higher fidelity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

This brief describes a common pattern of sophisticated command-and-control (C2) activity on Linux systems, often associated with C2 agents like Poseidon and Athena, which are known to integrate with C2 frameworks such as Mythic. The attack typically begins with the deployment and execution of a malicious loader or C2 agent into suspicious, writable Linux directories such as `/dev/shm`, `/tmp`, or `/var/tmp`. From these locations, the malicious process establishes an outbound network connection to its C2 server, continuously polling for commands via web requests. Upon receiving instructions, the agent proceeds to create new files on the system. These files can include staging scripts or additional payloads for subsequent execution, persistence mechanisms, or further post-exploitation activities, signaling an active and tasked implant.

## Attack Chain

1.  **Initial Access**: An attacker gains initial access to a Linux system through various means, including exploiting vulnerabilities in public-facing applications, phishing, or compromised credentials.
2.  **Loader Deployment & Execution**: A malicious loader or C2 agent, such as Poseidon or Athena, is deployed to and executed from a suspicious, writable directory like `/dev/shm`, `/tmp`, `/var/tmp`, or `/var/log`.
3.  **Command and Control (C2) Connection**: The executed agent initiates an outbound network connection from its precarious location to a remote command-and-control server, potentially part of a framework like Mythic.
4.  **C2 Polling for Commands**: The C2 agent continuously polls the remote server, typically using web protocols (e.g., HTTP/S GET/POST requests), to retrieve new commands or instructions.
5.  **File Creation for Staging**: Upon receiving commands from the C2, the agent creates a new file on the local filesystem within a suspicious writable directory (e.g., `/tmp/payload.sh` or a renamed binary) to stage a subsequent payload or script.
6.  **Execution or Persistence**: The newly created file is then executed by the C2 agent or configured for persistence, allowing the attacker to establish a more durable foothold, elevate privileges, or perform further malicious actions.
7.  **Post-Exploitation Activity**: With established control and persistence, the attacker proceeds with their objectives, which may include data exfiltration, lateral movement, or system disruption.

## Impact

If successful, this attack pattern can lead to complete compromise of the affected Linux system, enabling attackers to maintain persistence, execute arbitrary commands, and exfiltrate sensitive data. Victims may experience unauthorized access, data breaches, and disruption of critical services. While specific victim counts are not available for this general pattern, the impact can range from isolated system compromise to widespread network infiltration if lateral movement is achieved. The presence of such C2 agents indicates a significant security breach that requires immediate containment and remediation to prevent further damage.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and correlate `Linux Suspicious Outbound Network from Writable Directory` and `Linux Suspicious File Creation by Process in Writable Directory` events within a short time window (e.g., 5 seconds) for high-fidelity detection of this C2 pattern.
*   Ensure Elastic Defend is properly configured on all Linux endpoints to collect `network_connection` and `file_event` logs, which are essential for activating the rules above.
*   Implement stringent network egress filtering to limit outbound connections from Linux servers to only known, legitimate destinations, reducing the effectiveness of C2 beaconing.
*   Harden Linux systems by restricting execution permissions in commonly writable directories such as `/tmp`, `/dev/shm`, and `/var/tmp`, and enforce application allowlisting where feasible.
*   Review the process ancestry and launch context for any binaries observed connecting outbound or creating files from suspicious writable directories to identify the initial access vector.
