---
title: Potential DGA Activity Detected by Machine Learning
slug: 2024-01-dga-activity
description: A machine learning job detected potential DGA (domain generation algorithm) activity indicative of malware command and control (C2) channels, identifying source IP addresses making DNS requests with a high probability of being DGA-generated, a technique used by adversaries to evade detection.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
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

This brief describes a detection of potential DGA (Domain Generation Algorithm) activity identified by an Elastic machine learning job. DGAs are often used by malware for command and control (C2) communication, generating domain names dynamically to evade detection. The machine learning job, `dga_high_sum_probability_ea`, analyzes DNS requests to identify source IP addresses that exhibit a high probability of DGA activity. This detection relies on the DGA Detection integration, which includes an ML-based framework to detect DGA activity in DNS events. The integration requires Fleet and DNS events collected by integrations such as Elastic Defend, Network Packet Capture, or Packetbeat. This activity matters for defenders because successful DGA-based C2 channels can allow malware to maintain communication and control even when individual malicious domains are blocked.

## Attack Chain

1.  The attacker compromises a host within the network, potentially through unpatched vulnerabilities or social engineering.
2.  Malware is deployed on the compromised host. This malware contains a DGA.
3.  The malware uses the DGA to generate a list of potential domain names.
4.  The compromised host initiates DNS requests to resolve the generated domain names.
5.  The DNS requests are sent to internal or external DNS servers.
6.  The machine learning job `dga_high_sum_probability_ea` analyzes the DNS requests, specifically looking for source IPs with a high aggregate probability of generating DGA domains.
7.  If the anomaly score exceeds the threshold (70), an alert is triggered.
8.  The malware successfully establishes a C2 channel with a dynamically generated domain, enabling further malicious activities such as data exfiltration or lateral movement.

## Impact

The successful exploitation of DGA-based command and control can lead to persistent malware infections, data exfiltration, and further compromise of systems within the network. While the severity is rated low, the potential impact can escalate quickly if the C2 channel is used for more damaging activities. This detection focuses on identifying potential DGA activity, enabling security teams to investigate and prevent further damage.

## Recommendation

*   Ensure the DGA Detection integration is installed and properly configured, including the machine learning job `dga_high_sum_probability_ea` (references: [Elastic DGA Detection documentation](https://docs.elastic.co/en/integrations/dga), [prebuilt ML jobs](https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html)).
*   Verify that DNS events are being collected by Elastic Defend, Network Packet Capture, or Packetbeat and that the data view used by the machine learning job includes these events (references: [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint), [Network Packet Capture](https://docs.elastic.co/integrations/network_traffic), [Packetbeat](https://www.elastic.co/guide/en/beats/packetbeat/current/packetbeat-overview.html)).
*   Tune the anomaly threshold (currently 70) in the machine learning job based on your environment to reduce false positives and ensure timely detection of DGA activity.
*   Review and implement the triage and analysis steps outlined in the rule's note section, focusing on identifying the source IP, analyzing DNS request patterns, and cross-referencing domains with threat intelligence feeds.
