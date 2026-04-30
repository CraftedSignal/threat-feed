---
title: Unusually High Mean of RDP Session Duration Detected by Machine Learning
slug: 2024-01-high-mean-rdp-session
description: A machine learning job detected an unusually high mean of RDP session duration, indicative of potential lateral movement or persistent access attempts by adversaries abusing RDP.
date: "2024-01-24T18:10:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - lateral-movement
  - rdp
  - machine-learning
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
  - title: Detect RDP Connection with Uncommon Source IP
    description: Detects RDP connections where the source IP address is not commonly associated with RDP traffic, potentially indicating lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - network_connection
      - windows
  - title: Detect RDP Process Spawning Suspicious Child Process
    description: Detects the spawning of suspicious child processes from the RDP process, which might indicate malicious activity within an RDP session.
    platform: sigma
    severity: high
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1021.001
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect RDP Session with High Data Transfer
    description: Detects RDP sessions with unusually high data transfer, potentially indicating data exfiltration or other malicious activities.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1021.001
      - T1041
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This threat brief addresses the detection of unusually long Remote Desktop Protocol (RDP) sessions, identified by a pre-built Elastic machine learning job named `lmd_high_mean_rdp_session_duration_ea`. Attackers can abuse RDP for lateral movement and maintaining persistence within a network. Extended RDP sessions can also be used to evade detection mechanisms. This detection leverages machine learning to identify deviations from normal RDP session durations, potentially indicating malicious activity. The detection rule has been available since October 2023, and the corresponding ML job is part of the Lateral Movement Detection integration, requiring Elastic Stack version 9.4.0 or later. The rule depends on the `host.ip` field to be populated, which may require enabling host IP collection in Elastic Defend versions 8.18 and above.

## Attack Chain

1.  An attacker gains initial access to a system within the network, possibly through phishing or exploiting a public-facing application.
2.  The attacker leverages valid credentials or exploits a vulnerability to establish an RDP connection to a target system.
3.  The RDP session is maintained for an extended period, significantly longer than typical RDP sessions within the environment.
4.  During the prolonged RDP session, the attacker performs reconnaissance, gathering information about the network and target systems.
5.  The attacker moves laterally to other systems within the network, using the established RDP session as a persistent access point.
6.  The attacker executes malicious commands or transfers files, potentially installing malware or exfiltrating sensitive data.
7.  The unusually long RDP session duration helps the attacker to remain undetected and evade security measures.
8.  The attacker achieves their final objective, such as data theft, system compromise, or ransomware deployment.

## Impact

Successful exploitation and undetected lateral movement via prolonged RDP sessions can lead to significant data breaches, system compromise, and financial loss. The impact includes potential theft of sensitive information, disruption of business operations, and reputational damage. If an adversary establishes a persistent foothold via RDP, they can maintain long-term access to the compromised environment.

## Recommendation

*   Ensure `host.ip` field is populated by enabling host IP collection if using Elastic Defend versions 8.18 and above, as described in the [helper guide](https://www.elastic.co/docs/solutions/security/configure-elastic-defend/configure-data-volume-for-elastic-endpoint#host-fields).
*   Install and configure the Lateral Movement Detection integration in Kibana as described in the [setup guide](https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html).
*   Tune the machine learning job `lmd_high_mean_rdp_session_duration_ea` by adjusting the `anomaly_threshold` based on your environment and RDP usage patterns.
*   Investigate triggered alerts from the "High Mean of RDP Session Duration" rule following the [triage and analysis guide](https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html).
*   Monitor Windows RDP process events collected by the [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint) integration for suspicious activity.
