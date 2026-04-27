---
title: Unusual Remote File Size Indicating Lateral Movement
slug: 2024-04-30-unusual-remote-file-size
description: A machine learning job has detected an unusually high file size shared by a remote host, indicating potential lateral movement as attackers bundle data into a single large file transfer to evade detection when exfiltrating valuable information.
date: "2024-04-30T10:00:00Z"
severities:
  - low
tags:
  - lateral-movement
  - data-exfiltration
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
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1039
    technique_name: Data from Network Shared Drive
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/lmd
  - https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration
  - https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security
rules:
  - title: High File Size Transfer via RDP
    description: Detects unusually high file sizes transferred via RDP, potentially indicating lateral movement and data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1570
    data_sources:
      - network_connection
      - windows
  - title: Suspiciously Large File Creation in User Directory
    description: Detects the creation of a suspiciously large file within a user's directory, which may precede a remote transfer.
    platform: sigma
    severity: low
    tactics:
      - collection
    techniques:
      - T1039
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This detection leverages machine learning to identify unusual remote file sizes, a tactic often used during lateral movement. After gaining initial access, adversaries frequently aim to locate and exfiltrate valuable data. To avoid raising alarms with numerous small transfers, they may consolidate data into a single large file. This rule, built upon the Elastic Lateral Movement Detection integration, specifically uses the `lmd_high_file_size_remote_file_transfer_ea` machine learning job. The…
