---
title: GlassWorm Campaign Deploying Wave 3 Windows Payload
slug: 2024-01-glassworm-wave3
description: The GlassWorm campaign has been observed deploying a Wave 3 Windows payload, indicating ongoing malicious activity targeting Windows systems.
date: "2026-03-16T15:00:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - glassworm
  - malware
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.reddit.com/r/netsec/comments/1rvbu61/glassworm_part_3_wave_3_windows_payload/
  - https://codeberg.org/tip-o-deincognito/glassworm-writeup/src/branch/main/PART3.md
rules:
  - title: Detect Unknown Windows Executable Execution
    description: Detects the execution of unknown or unsigned Windows executables, which could indicate the presence of malware such as the GlassWorm Wave 3 payload.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Network Connection by Unknown Executable
    description: Detects network connections initiated by executables not typically associated with network activity.  This could indicate command and control or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The GlassWorm campaign has been identified deploying a Wave 3 Windows payload. This indicates a continuation of the threat actor's operations, with an updated payload targeting Windows systems. The specifics of the delivery mechanism and the exact functionality of the Wave 3 payload are currently unknown. Defenders should be aware of the ongoing GlassWorm activity and implement detections for suspicious Windows executables. Further analysis is required to fully understand the capabilities of the Wave 3 payload and the scope of the campaign.

## Attack Chain

1.  Initial Access: The initial access vector is unknown.
2.  Payload Delivery: A Wave 3 Windows payload is delivered to the system.
3.  Execution: The Windows payload is executed.
4.  Persistence: The payload establishes persistence on the system.
5.  Command and Control: The payload connects to a command and control server for instructions.
6.  Data Collection: The payload gathers sensitive data from the system.
7.  Exfiltration: The collected data is exfiltrated to the attacker.

## Impact

The successful deployment of the GlassWorm Wave 3 payload could lead to data theft, system compromise, and potential financial loss. The impact depends on the specific objectives of the threat actor and the sensitivity of the data compromised. The lack of specific information about victimology makes determining the overall scope impossible.

## Recommendation

*   Monitor process creation events for unknown or unsigned executables, especially those with network connections (reference: process_creation and network_connection log sources).
*   Investigate any alerts related to the execution of potentially malicious Windows executables.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
