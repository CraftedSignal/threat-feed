---
title: Unusually High Mean of RDP Session Duration Detected by Machine Learning
slug: 2024-01-high-mean-rdp-session
description: A machine learning job detected an unusually high mean of RDP session duration, indicative of potential lateral movement or persistent access attempts by adversaries abusing RDP.
date: "2024-01-24T18:10:00Z"
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

This threat brief addresses the detection of unusually long Remote Desktop Protocol (RDP) sessions, identified by a pre-built Elastic machine learning job named `lmd_high_mean_rdp_session_duration_ea`. Attackers can abuse RDP for lateral movement and maintaining persistence within a network. Extended RDP sessions can also be used to evade detection mechanisms. This detection leverages machine learning to identify deviations from normal RDP session durations, potentially indicating malicious…
