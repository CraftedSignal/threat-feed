---
title: Detection of High-Frequency File Operations in Administrative Network Shares
slug: 2026-08-high-frequency-network-share-copy
description: An anomaly-based detection analytic identifying potential insider threats or data exfiltration by monitoring for high-frequency write operations to administrative network shares via Windows Event ID 5145.
date: "2026-08-05T21:12:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - insider-threat
  - data-exfiltration
  - windows
  - monitoring
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: The following analytic detects a high frequency of file copying or moving within network shares, which may indicate potential data sabotage or exfiltration attempts.
    confidence_band: high
rules:
  - title: Detect High Frequency File Copy To Admin Shares
    description: Detects anomalous high-frequency file write operations to administrative network shares (Admin$, C$, IPC$) which may indicate data exfiltration or sabotage.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable Object Audit access for Event ID 5145 in GPO
      owner: IT Operations
      due: 72h
      evidence: Required for detection implementation
  enrichment_needed:
    - item: User baselining
      owner: Detection Engineering
      reason: Reduce false positives by establishing normal user copy patterns
      evidence: Analytic relies on statistical deviations
  mitigation_plan:
    - priority: medium_term
      action: Restrict access to administrative shares (Admin$, C$) to authorized service accounts only
      owner: IT Operations
      addresses: T1537
      evidence: Administrative shares are primary targets for lateral movement and data staging
---

This detection analytic identifies suspicious file activity within Windows environments, focusing on administrative network shares (Admin$, C$, and IPC$). By analyzing Windows Security Event Log 5145, the analytic tracks write and append operations on common file types, including documents, archives, and logs. This mechanism is designed to detect insider threats, unauthorized data staging, or exfiltration attempts, as well as potential data sabotage. 

The detection logic functions by establishing a baseline for file-write volume per user and destination host. It flags instances where write activity exceeds three standard deviations from the user's historical average or crosses a defined threshold of 20 events within a 5-minute window. This approach helps filter out routine, authorized network traffic while highlighting anomalous batch-processing or manual mass-copying behaviors often associated with malicious intent or compromised credentials.

## Impact

Successful exploitation of the behaviors monitored by this analytic could lead to unauthorized access, massive data exfiltration, or the deletion of evidence by an insider or an attacker who has moved laterally within the network. This activity has been observed in the context of information sabotage and has been linked to potential exfiltration phases for ransomware campaigns.

## Recommendation

* Enable Windows Security Event Log 5145 (Object Access) via Group Policy on all endpoints serving as network shares.
* Ensure Windows Security Event Logs are being forwarded and ingested into the SIEM.
* Deploy the detection logic provided in the SIEM to baseline user behavior and tune the thresholds (e.g., the 20-event limit) based on the organization's normal file-sharing volume.
* Investigate alerts flagged by this logic by reviewing the source user and source IP associated with the anomalous write volume.
* Cross-reference detected alerts with user access logs to determine if the activity is aligned with the user's job role and typical workstation behavior.
