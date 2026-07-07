---
title: 'Suspicious Linux C2 Activity: Network Connection Followed by File Creation'
slug: 2026-07-suspicious-linux-c2-activity
description: This brief identifies suspicious Command and Control (C2) activity on Linux systems where a C2 agent, such as Poseidon or Athena, connects outbound from a sensitive temporary directory and subsequently creates a file in a similar location, indicative of receiving and executing commands from a C2 framework like Mythic.
date: "2026-07-03T15:14:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - execution
  - linux
  - endpoint-detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This behavior is consistent with C2 agents such as Poseidon and Athena, connecting to a C2 framework such as Mythic. The agent polls the C2 for commands through a web request.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The agent polls the C2 for commands through a web request, after which the command gets executed.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_netcon_file_creation.toml
rules:
  - title: Suspicious Process Network Connection from Writable Path on Linux
    description: Detects outbound network connections initiated by a process executing from a common temporary or writable directory on Linux, indicative of C2 agent activity.
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
  - title: Suspicious File Creation by Process in Writable Path on Linux
    description: Detects suspicious file creation events on Linux by processes executing from common temporary or writable directories, a behavior often associated with C2 agent operations.
    platform: sigma
    severity: low
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

This threat brief describes a pattern of suspicious activity on Linux systems consistent with the operation of Command and Control (C2) agents like Poseidon or Athena. These agents often operate from non-standard, writable directories such as `/tmp`, `/dev/shm`, or `/var/log` to evade detection. The observed behavior involves such a process first initiating an outbound network connection, typically polling a C2 framework like Mythic for commands or new payloads. This network communication is then rapidly followed by the creation of a new file by the same process, usually in another suspicious location on the system. This file creation event often indicates the agent receiving and staging further instructions or malicious components. Defenders should recognize this two-stage sequence as a strong indicator of post-compromise activity, potentially leading to data exfiltration, lateral movement, or further system compromise.

## Attack Chain

1.  **C2 Agent Deployment**: An attacker successfully deploys a C2 agent (e.g., Poseidon, Athena) to a non-standard, writable location on a Linux host, such as `/tmp`, `/dev/shm`, `/var/tmp`, `/var/log`, `/var/run/user`, or `/run/user`.
2.  **Outbound C2 Connection**: The deployed C2 agent initiates an outbound network connection (e.g., HTTP/S web requests) to its C2 server, potentially part of a C2 framework like Mythic, to poll for new commands or payloads.
3.  **Command Reception**: The C2 server responds to the agent's poll, sending commands, scripts, or additional malicious binaries back to the compromised host.
4.  **Local File Creation**: The C2 agent creates a new file on the local filesystem, often in a similar suspicious writable directory, to store the received commands, scripts, or payloads.
5.  **Command Execution**: The C2 agent proceeds to execute the newly created file or the commands received, leading to further actions on objectives such as data collection, privilege escalation, or lateral movement.

## Impact

Successful execution of such C2 agent activity can lead to a range of severe consequences. Attackers can maintain persistent access to the compromised Linux system, exfiltrate sensitive data, install additional malware, establish backdoors, or use the system as a launchpad for lateral movement within the network. Since this behavior is characteristic of established C2 frameworks, victims could face significant financial losses, reputational damage, and regulatory penalties depending on the type and sensitivity of compromised data. The lack of specifics in this detection means the full scope of impact can only be assessed upon incident response.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious network connections and file creations from writable directories.
*   Ensure comprehensive `network_connection` and `file_event` logging is enabled on all Linux endpoints to capture the necessary telemetry for these detections.
*   Implement correlation rules in your SIEM to link network connections from suspicious processes with subsequent file creations by the same process within a short timeframe, mimicking the original EQL rule's logic.
*   Regularly review processes executing from temporary or shared memory directories (`/tmp`, `/dev/shm`, `/var/tmp`) for anomalous network activity or file system modifications, as detected by the rules above.
*   Investigate all alerts generated by the `Suspicious Process Network Connection from Writable Path on Linux` rule, especially those involving connections to external or unusual IP addresses.
*   Analyze processes identified by the `Suspicious File Creation by Process in Writable Path on Linux` rule, focusing on the content of the created files and the parent process responsible.
