---
title: Detection of Suspicious C2 Named Pipe Activity
slug: 2026-10-suspicious-c2-named-pipes
description: This brief details a detection strategy for identifying the creation or connection to known malicious named pipes used by C2 frameworks like Cobalt Strike and Brute Ratel to facilitate post-exploitation communication.
date: "2026-10-05T12:28:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - c2
  - persistence
  - execution
  - windows
  - ipc
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1021.002
    technique_name: SMB/Windows Admin Shares
    evidence: The following analytic detects the creation or connection to known suspicious C2 named pipes.
    confidence_band: high
rules:
  - title: Detect Suspicious C2 Named Pipe Usage
    description: Detects processes interacting with known C2-related named pipes using Sysmon events.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1021.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable Sysmon Event ID 17 and 18 collection
      owner: SOC
      due: 48h
  hunt_leads:
    - lead: Identify processes communicating over pipes not associated with known software
      technique_id: T1021.002
      priority: medium
      confidence: medium
      disposition: hunt_now
---

Attackers frequently utilize Windows named pipes to establish inter-process communication (IPC) channels for Command and Control (C2), process injection, and lateral movement. Many post-exploitation frameworks, including Cobalt Strike, Brute Ratel, and various ransomware variants, rely on unique or default pipe naming conventions to maintain stealthy persistence and execute malicious commands. By leveraging Sysmon Event IDs 17 (Pipe Created) and 18 (Pipe Connected), defenders can identify processes that interact with these specific, high-risk pipe patterns. This analytic is designed to minimize noise by filtering out common legitimate Windows and third-party application paths, allowing security operations centers to focus on potentially unauthorized IPC activity indicative of active threat actor infrastructure.

## Attack Chain

1. Attacker achieves initial execution on the target Windows endpoint.
2. Malware or C2 agent spawns to establish a foothold on the system.
3. The agent initiates a named pipe server or client connection to facilitate internal IPC.
4. The malicious process uses these pipes for process injection or to communicate with sub-processes.
5. The C2 agent receives instructions from the attacker through the established communication tunnel.
6. Attacker performs post-exploitation tasks such as credential dumping, lateral movement, or data exfiltration.

## Impact

Successful exploitation of this mechanism allows attackers to maintain persistence, execute code within the memory space of legitimate processes, and bypass traditional network-based security controls by tunneling malicious traffic through local IPC channels. Observed impacts include ransomware deployment, credential theft, and full system compromise across various incident response scenarios involving frameworks like Cobalt Strike, Brute Ratel, and Trickbot.

## Recommendation

* Enable Sysmon logging with a focus on Event ID 17 and Event ID 18 to gain visibility into pipe operations.
* Deploy the provided Sigma detection rule to identify processes interacting with known C2-related named pipes.
* Investigate any hits on non-standard processes, especially those executing from Temp or AppData directories.
* Tune the process exclusion list based on your environment's baseline behavior to reduce false positives.
