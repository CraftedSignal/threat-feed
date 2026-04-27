---
title: Unusual Spike in Bytes Written to External Device Detected by Machine Learning
slug: 2026-04-high-bytes-written-to-external-device
description: A machine learning job has detected a spike in bytes written to an external device, which is anomalous and can signal illicit data copying or transfer activities, potentially leading to data exfiltration.
date: "2026-04-02T12:00:00Z"
severities:
  - low
tags:
  - data exfiltration
  - machine learning
  - external device
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
  - title: Potential Data Exfiltration via High Bytes Written to Removable Media (Process)
    description: Detects a process writing a significant number of bytes to a removable drive, potentially indicating data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1052.001
    data_sources:
      - process_creation
      - windows
  - title: Potential Data Exfiltration via High Bytes Written to Removable Media (File Event)
    description: Detects a significant number of bytes written to removable media, potentially indicating data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1052.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The Data Exfiltration Detection integration, part of the Elastic Security suite, includes a machine learning job designed to detect anomalies in data transfer patterns to external devices. This job, named "ded_high_bytes_written_to_external_device," identifies unusual increases in the amount of data written to external devices, which could indicate data exfiltration attempts. The system establishes a baseline of normal activity and flags deviations from that baseline, operating on a 15-minute…
