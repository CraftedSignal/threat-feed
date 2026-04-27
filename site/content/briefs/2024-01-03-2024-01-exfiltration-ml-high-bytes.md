---
title: Machine Learning Detects High Bytes Written to External Device
slug: 2024-01-exfiltration-ml-high-bytes
description: A machine learning job has detected high bytes of data written to an external device, potentially indicating illicit data copying or transfer activities leading to data exfiltration over a physical medium such as USB.
date: "2024-01-03T15:00:00Z"
severities:
  - low
tags:
  - data-exfiltration
  - machine-learning
  - endpoint
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1052
    technique_name: Exfiltration Over Physical Medium
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/ded
  - https://www.elastic.co/blog/detect-data-exfiltration-activity-with-kibanas-new-integration
rules:
  - title: Detect High Bytes Written to External Device (File Events)
    description: Detects a significant increase in the number of bytes written to a removable disk, potentially indicating data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1052.001
    data_sources:
      - file_event
      - windows
  - title: Detect High Bytes Written to External Device (Process Creation)
    description: Detects processes writing large amounts of data to removable drives, potentially indicating data exfiltration.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1052.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief addresses a machine learning detection identifying anomalous data transfer volumes to external devices. The Elastic Data Exfiltration Detection integration includes a prebuilt machine learning job, `ded_high_bytes_written_to_external_device_ea`, designed to detect spikes in data written to external devices. This behavior is considered anomalous because typical operational settings usually exhibit predictable patterns or ranges of data transfer to external storage. The detection is…
