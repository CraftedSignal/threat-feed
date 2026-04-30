---
title: Unusual Remote File Extension Detected via Machine Learning
slug: 2024-01-03-unusual-remote-file-extension
description: An Elastic machine learning rule detects unusual remote file transfers with rare extensions, potentially indicating lateral movement activity on a host and suggesting adversaries bypassing security measures.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
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

This brief focuses on a detection rule from Elastic's Lateral Movement Detection (LMD) integration that utilizes machine learning to identify unusual remote file transfers. The rule, "Unusual Remote File Extension," is designed to detect anomalies in file transfers, specifically those involving rare file extensions, which could be indicative of lateral movement within a network. This rule leverages the `lmd_rare_file_extension_remote_transfer_ea` machine learning job ID. The rule requires the Lateral Movement Detection integration assets to be installed, as well as file and Windows RDP process events collected by the Elastic Defend integration. The rule operates by analyzing `host.ip` and detecting anomalies in file transfers, where host IP collection needs to be enabled on Elastic Defend versions 8.18 and above.

## Attack Chain

1. An attacker gains initial access to a system within the network.
2. The attacker attempts to move laterally to other systems using remote services like RDP or SMB.
3. As part of the lateral movement, the attacker transfers tools or files to the remote system.
4. The attacker uses a rare or uncommon file extension for the transferred files, potentially to evade detection based on known file types.
5. The file transfer occurs over the network, triggering file event logs on the source and destination systems.
6. Elastic Defend, with host IP collection enabled, monitors these file events and forwards the data to the Elastic Security platform.
7. The "Unusual Remote File Extension" machine learning job identifies the transfer of a file with a rare extension, comparing it against historical data.
8. If the file extension is deemed anomalous based on its rarity, the rule triggers, indicating potential lateral movement.

## Impact

A successful lateral movement attack can allow an adversary to gain access to sensitive data, critical systems, or privileged accounts. By using uncommon file extensions, attackers attempt to bypass security measures that rely on identifying known file types. This can lead to undetected malware deployment, data exfiltration, or further compromise of the network. Though this rule is of low severity, it can provide an early warning signal to stop an attack before greater damage occurs.

## Recommendation

*   Enable the `host.ip` field within Elastic Defend configurations (versions 8.18 and above) to ensure proper data collection for the machine learning job.
*   Install the Lateral Movement Detection integration assets within Kibana as per the provided setup instructions to activate the "Unusual Remote File Extension" rule.
*   Tune the anomaly threshold of the machine learning job to reduce false positives, considering your organization's typical file transfer patterns.
*   Deploy the "Detect Remote File Extension Transfer" Sigma rule to identify file transfers with rare extensions using process creation logs.
*   Review the triage and analysis steps in the rule's documentation to effectively investigate and respond to triggered alerts.
