---
title: Spike in Number of Processes in an RDP Session
slug: 2024-01-rdp-process-spike
description: A machine learning job has detected an unusually high number of processes started within a single Remote Desktop Protocol (RDP) session, potentially indicating lateral movement activity.
date: "2024-01-23T14:35:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - lateral-movement
  - threat-detection
  - windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/lmd
  - https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration
  - https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security
rules:
  - title: Detect High Number of Processes Created by a Single User via RDP
    description: Detects a high number of process creations by a single user within a short timeframe during an RDP session, indicating possible lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - process_creation
      - windows
  - title: Detect RDP Session with Suspicious Process Name
    description: Detects a suspicious process being created during an RDP session. This may indicate lateral movement activity.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies potential lateral movement by flagging spikes in the number of processes initiated during a single RDP session. The rule, based on an Elastic machine learning job named `lmd_high_sum_rdp_number_of_processes_ea`, aims to uncover suspicious remote activity indicative of an attacker attempting to execute commands or deploy tools on a compromised host. This detection matters because RDP is a common vector for attackers to gain access to internal networks and subsequently move laterally. The detection leverages Windows RDP process events and file events collected by the Elastic Defend integration. Identifying anomalous process creation within RDP sessions can help defenders identify and respond to potential security incidents faster.

## Attack Chain

1. An attacker gains initial access to a system within the network.
2. The attacker leverages valid credentials or exploits an RDP vulnerability to establish a remote session (T1021.001).
3. Once connected via RDP, the attacker begins to execute a series of commands to enumerate the system and network.
4. The attacker attempts to install malware or other malicious tools, triggering the creation of multiple processes.
5. The machine learning job detects a significant increase in the number of processes started within the RDP session.
6. The detection rule triggers, alerting analysts to the anomalous activity.
7. The attacker uses the newly installed tools to move laterally to other systems on the network.
8. The attacker achieves their objective, such as data exfiltration or ransomware deployment.

## Impact

A successful lateral movement attack can lead to significant damage, including data breaches, system compromise, and financial loss. While the severity is low, a spike in RDP processes can be an early indicator of compromise. Attackers often use RDP to propagate through a network after gaining initial access, making this detection critical for preventing widespread damage.

## Recommendation

*   Enable host IP collection by following the configuration steps in the [Elastic Defend documentation](https://www.elastic.co/docs/solutions/security/configure-elastic-defend/configure-data-volume-for-elastic-endpoint#host-fields) to ensure the `host.ip` field is populated.
*   Install the Lateral Movement Detection integration assets as described in the rule's setup instructions to enable the machine learning job `lmd_high_sum_rdp_number_of_processes_ea`.
*   Review and tune the anomaly threshold to reduce false positives based on your organization's typical RDP usage.
*   Investigate RDP sessions flagged by this rule to identify the source of the process spike and potential malicious activity as described in the rule's "Triage and Analysis" notes.
