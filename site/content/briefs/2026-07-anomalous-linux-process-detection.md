---
title: Anomalous Process For a Linux Population Detection
slug: 2026-07-anomalous-linux-process-detection
description: Elastic has released a machine learning detection rule designed to identify rare and unusual process executions across multiple Linux hosts within an entire fleet, aiming to uncover potential malware or suspicious behaviors indicative of persistence or other malicious activity.
date: "2026-07-27T15:35:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - linux
  - machine-learning
  - threat-detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: The rule description indicates it aims to 'uncover potential malware and suspicious behaviors'; malware frequently achieves persistence by creating or modifying system processes.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/persistence_ml_linux_anomalous_process_all_hosts.toml
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
---

Elastic has released a machine learning detection rule, "Anomalous Process For a Linux Population", designed to identify rare and unusual process executions across multiple Linux hosts within an entire fleet. Published on July 27, 2026, this rule leverages machine learning to establish baselines of legitimate activity and reduce false positives typically associated with single-machine anomaly detection. Its purpose is to uncover potential malware and suspicious behaviors indicative of persistence or other malicious activity by flagging processes that deviate from the normal operational patterns across a population of hosts. The rule is available for Elastic users leveraging Elastic Defend, Auditd Manager, or Network Packet Capture integrations.

## Impact

Failure to detect anomalous processes can allow attackers to maintain persistence within an environment, execute arbitrary code, or exfiltrate sensitive data without immediate detection. Undetected malware or suspicious processes could lead to complete system compromise, data breaches, and significant operational disruption. This rule aims to identify such activity early, mitigating the risk of prolonged attacker presence and the associated financial and reputational damage to organizations.

## Recommendation

* Enable Elastic Defend, Auditd Manager, or Network Packet Capture integrations to feed necessary process execution data into Elastic Security.
* Deploy the associated Machine Learning job "v3_linux_anomalous_process_all_hosts_ea" as part of the "Anomalous Process For a Linux Population" rule within Elastic Security.
* Investigate processes flagged by the "Anomalous Process For a Linux Population" rule by examining their execution chain, prevalence, location, and associated user activity.
* Review arguments and working directories of anomalous processes to determine their origin and purpose.
* Establish exceptions for known benign, rare processes, such as newly installed software or infrequently run maintenance tasks, to reduce false positives.
