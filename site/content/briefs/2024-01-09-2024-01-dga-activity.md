---
title: Potential DGA Activity Detected by Machine Learning
slug: 2024-01-dga-activity
description: A machine learning job detected potential DGA (domain generation algorithm) activity indicative of malware command and control (C2) channels, identifying source IP addresses making DNS requests with a high probability of being DGA-generated, a technique used by adversaries to evade detection.
date: "2024-01-09T15:00:00Z"
severities:
  - low
tags:
  - dga
  - command-and-control
  - machine-learning
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1568
    technique_name: Dynamic Resolution
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/dga
  - https://www.elastic.co/security-labs/detect-domain-generation-algorithm-activity-with-new-kibana-integration
rules:
  - title: DNS Request to High Probability DGA Domain
    description: Detects DNS queries to domains identified as high probability DGA by machine learning.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1568.002
    data_sources:
      - dns_query
      - zeek
  - title: Process Making DNS Requests to Multiple Unique Domains
    description: Detects processes that initiate DNS requests to multiple unique domains within a short timeframe, potentially indicating DGA activity.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1568.002
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

This brief describes a detection of potential DGA (Domain Generation Algorithm) activity identified by an Elastic machine learning job. DGAs are often used by malware for command and control (C2) communication, generating domain names dynamically to evade detection. The machine learning job, `dga_high_sum_probability_ea`, analyzes DNS requests to identify source IP addresses that exhibit a high probability of DGA activity. This detection relies on the DGA Detection integration, which includes…
