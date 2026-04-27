---
title: Spike in Remote File Transfers via Lateral Movement
slug: 2024-01-spike-remote-file-transfers
description: A machine learning job detects an abnormal volume of remote file transfers, potentially indicating lateral movement by attackers attempting to blend in with normal network egress activity.
date: "2024-01-02T12:00:00Z"
severities:
  - low
tags:
  - lateral-movement
  - machine-learning
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/lmd
  - https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration
  - https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security
rules:
  - title: Detect Remote File Transfers via Uncommon Processes
    description: Detects remote file transfers initiated by processes that are not typically associated with network activity, which may indicate lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1570
    data_sources:
      - process_creation
      - windows
  - title: Detect High Volume SMB Traffic
    description: Detects an unusual volume of Server Message Block (SMB) traffic, which can be indicative of lateral movement activities.
    platform: sigma
    severity: low
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The "Spike in Remote File Transfers" detection identifies potential lateral movement activity within a network by monitoring for unusual volumes of remote file transfers. Attackers often aim to locate and exfiltrate valuable information after gaining initial access. To evade detection, they may attempt to mimic normal egress activity through numerous small transfers. This detection leverages machine learning to establish a baseline of normal transfer activity and identify deviations that may…
