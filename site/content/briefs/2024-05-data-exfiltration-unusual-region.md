---
title: Potential Data Exfiltration to Unusual Geographic Region via Machine Learning
slug: 2024-05-data-exfiltration-unusual-region
description: A machine learning job has detected potential data exfiltration activity to an unusual geographical region, specifically by region name, indicating exfiltration over command and control channels.
date: "2024-05-02T10:00:00Z"
severities:
  - low
tags:
  - data-exfiltration
  - machine-learning
  - network-traffic
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/ded
  - https://www.elastic.co/blog/detect-data-exfiltration-activity-with-kibanas-new-integration
rules:
  - title: Detect Network Connection to Unusual Geo Region
    description: Detects processes initiating network connections to unusual geographical regions.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
  - title: Detect High Sent Bytes to Unusual Geo Region
    description: Detects processes sending unusually high bytes to unusual geographical regions based on network connection logs.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This alert is triggered by a machine learning job, `ded_high_sent_bytes_destination_region_name_ea`, that detects data exfiltration to unusual geographical regions based on network traffic patterns. The Data Exfiltration Detection integration, including Elastic Defend and Network Packet Capture, is required for this detection to function. This integration analyzes network and file events to identify abnormalities in data transfer volumes to different geographical locations, specifically by…
