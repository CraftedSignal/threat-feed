---
title: Unusual Process Writing Data to an External Device via Machine Learning
slug: 2024-01-rare-process-exfiltration
description: A machine learning job detects a rare process writing data to an external device, potentially indicating data exfiltration masked by benign-looking processes.
date: "2024-01-02T12:00:00Z"
severities:
  - low
tags:
  - data-exfiltration
  - machine-learning
  - elastic-defend
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
  - title: Detect Rare Process Writing to Removable Media (Sysmon)
    description: Detects a process that is not commonly seen writing data to removable media (USB drives, external hard drives) using Sysmon event data.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1052.001
    data_sources:
      - file_event
      - windows
  - title: Detect Rare Process Writing to Removable Media (Process Creation)
    description: Detects a process that is not commonly seen writing data to removable media by monitoring process creation events and looking for command-line arguments indicating file writes to typical removable media paths.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1052.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies unusual processes writing data to external devices, a tactic often used by malicious actors to exfiltrate data while masking their activities with seemingly benign processes. The detection leverages machine learning to identify deviations from typical behavior patterns, specifically focusing on processes that have no legitimate reason to write data to external devices. The rule relies on the "ded_rare_process_writing_to_external_device_ea" machine learning job from the…
