---
title: Unusual Remote File Directory Lateral Movement Detection
slug: 2024-01-22-unusual-remote-file-directory
description: An Elastic machine learning job detects anomalous remote file transfers to unusual directories, indicating potential lateral movement by attackers attempting to bypass standard security monitoring.
date: "2024-01-22T12:00:00Z"
severities:
  - low
tags:
  - lateral-movement
  - machine-learning
  - elastic
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
  - title: Detect Remote File Creation in Uncommon Directory
    description: Detects file creation events in directories rarely used for file transfers, which could indicate lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1570
    data_sources:
      - file_event
      - windows
  - title: Detect Remote File Transfer via RDP to Uncommon Directory
    description: Detects files written via RDP (terminalservices-client) to directories rarely used for file transfers.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1570
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies potential lateral movement within a network by flagging unusual remote file transfers to directories that are not commonly monitored. Attackers often leverage less scrutinized file paths to evade standard security measures and deploy malicious payloads. This detection relies on the "lmd_rare_file_path_remote_transfer_ea" machine learning job within Elastic Security, which analyzes file and Windows RDP process events to identify anomalous file transfers based on the…
