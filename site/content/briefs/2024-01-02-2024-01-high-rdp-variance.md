---
title: High Variance in RDP Session Duration Detected via Machine Learning
slug: 2024-01-high-rdp-variance
description: A machine learning job has detected unusually high variance of RDP session duration, potentially indicating lateral movement and session persistence by threat actors.
date: "2024-01-02T10:00:00Z"
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
  - title: Detect RDP Session Connection via Uncommon Process
    description: Detects RDP session connection initiated from processes other than the standard RDP client (mstsc.exe).
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Network Connection to RDP Port
    description: Detects network connections to the standard RDP port (3389) initiated by unusual processes.
    platform: sigma
    severity: low
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This threat brief addresses the detection of high variance in Remote Desktop Protocol (RDP) session durations using machine learning. The detection, implemented in Elastic Security's Lateral Movement Detection integration, aims to identify anomalous RDP usage patterns that may indicate malicious activity. Adversaries might establish long RDP sessions to maintain persistence and move laterally within a network. The prebuilt Elastic ML job "lmd_high_var_rdp_session_duration_ea" analyzes RDP…
