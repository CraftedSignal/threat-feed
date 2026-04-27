---
title: Spike in Bytes Sent to an External Device via Airdrop
slug: 2024-01-airdrop-exfiltration
description: A machine learning job has detected a spike in bytes of data written to an external device via Airdrop, potentially indicating illicit data copying or transfer activities.
date: "2024-01-03T15:30:00Z"
severities:
  - low
tags:
  - data-exfiltration
  - macos
  - airdrop
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1011
    technique_name: Exfiltration Over Other Network Medium
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/ded
  - https://www.elastic.co/blog/detect-data-exfiltration-activity-with-kibanas-new-integration
rules:
  - title: Detect Airdrop Usage via Process Creation
    description: Detects the execution of the Airdrop process on macOS, which can be indicative of file transfers.
    platform: sigma
    severity: informational
    tactics:
      - exfiltration
    techniques:
      - T1011
    data_sources:
      - process_creation
      - macos
  - title: Detect Airdrop Transfer via Network Connection
    description: Detects network connections associated with Airdrop file transfers by monitoring for specific port or protocol usage.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1011
    data_sources:
      - network_connection
      - macos
rules_count: 2
---

This detection identifies potential data exfiltration attempts via Apple's Airdrop feature. A machine learning job monitors the volume of data transferred to external devices and flags unusual spikes. While Airdrop facilitates legitimate file sharing between Apple devices, it can be abused by malicious actors to exfiltrate sensitive data. This rule leverages the "ded_high_bytes_written_to_external_device_airdrop_ea" machine learning job and requires the Data Exfiltration Detection integration…
