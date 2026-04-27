---
title: Unusual Remote File Extension Detected via Machine Learning
slug: 2024-01-03-unusual-remote-file-extension
description: An Elastic machine learning rule detects unusual remote file transfers with rare extensions, potentially indicating lateral movement activity on a host and suggesting adversaries bypassing security measures.
date: "2024-01-03T15:00:00Z"
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
  - title: Detect Remote File Extension Transfer
    description: Detects the creation of files with unusual or suspicious extensions transferred from a remote source.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1570
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Program Executing from Unusual Extension
    description: Detects a program running with a less common file extension like .tmp, which may indicate a file transfer.
    platform: sigma
    severity: high
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1210
      - T1570
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on a detection rule from Elastic's Lateral Movement Detection (LMD) integration that utilizes machine learning to identify unusual remote file transfers. The rule, "Unusual Remote File Extension," is designed to detect anomalies in file transfers, specifically those involving rare file extensions, which could be indicative of lateral movement within a network. This rule leverages the `lmd_rare_file_extension_remote_transfer_ea` machine learning job ID. The rule requires the…
