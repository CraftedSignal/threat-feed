---
title: Spike in Number of Processes in an RDP Session
slug: 2024-01-rdp-process-spike
description: A machine learning job has detected an unusually high number of processes started within a single Remote Desktop Protocol (RDP) session, potentially indicating lateral movement activity.
date: "2024-01-23T14:35:00Z"
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

This detection identifies potential lateral movement by flagging spikes in the number of processes initiated during a single RDP session. The rule, based on an Elastic machine learning job named `lmd_high_sum_rdp_number_of_processes_ea`, aims to uncover suspicious remote activity indicative of an attacker attempting to execute commands or deploy tools on a compromised host. This detection matters because RDP is a common vector for attackers to gain access to internal networks and subsequently…
