---
title: Machine Learning Detects High Bytes Written to External Device
slug: 2024-01-exfiltration-ml-high-bytes
description: A machine learning job has detected high bytes of data written to an external device, potentially indicating illicit data copying or transfer activities leading to data exfiltration over a physical medium such as USB.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
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

This brief addresses a machine learning detection identifying anomalous data transfer volumes to external devices. The Elastic Data Exfiltration Detection integration includes a prebuilt machine learning job, `ded_high_bytes_written_to_external_device_ea`, designed to detect spikes in data written to external devices. This behavior is considered anomalous because typical operational settings usually exhibit predictable patterns or ranges of data transfer to external storage. The detection is triggered when the amount of data written significantly deviates from the established baseline, potentially signaling unauthorized data copying or exfiltration attempts. This detection focuses on identifying abnormalities, providing an alert for investigation of possible illicit data transfer activities. The integration requires the Elastic Defend integration to collect file events.

## Attack Chain

1. An attacker gains initial access to a system via compromised credentials or exploiting a vulnerability.
2. The attacker uses their access to locate and stage sensitive data for exfiltration.
3. The attacker connects an external storage device, such as a USB drive, to the compromised system.
4. The attacker initiates a large data transfer operation, copying the staged data to the external device.
5. Elastic Defend monitors file events and detects a significant increase in bytes written to the external device.
6. The `ded_high_bytes_written_to_external_device_ea` machine learning job identifies the unusual data transfer volume.
7. An alert is triggered based on the anomaly threshold defined in the Data Exfiltration Detection rule.
8. The attacker removes the external device, completing the exfiltration of the sensitive data.

## Impact

Successful exfiltration of data to external devices can lead to significant data breaches. The impact varies depending on the sensitivity and volume of the data stolen. This activity can result in financial losses, reputational damage, legal repercussions, and compromise of intellectual property. While the specific number of affected organizations is unknown, any organization that allows the use of external storage devices is potentially vulnerable. This issue poses a risk across various sectors, particularly those handling sensitive data, such as finance, healthcare, and technology.

## Recommendation

*   Install the Data Exfiltration Detection integration and configure the preconfigured anomaly detection jobs as described in the rule's setup instructions.
*   Review and tune the `anomaly_threshold` (currently set to 75) based on your environment's baseline data transfer patterns to reduce false positives.
*   Deploy endpoint detection and response (EDR) solutions to enhance visibility and control over data movements to external devices as mentioned in the "Response and remediation" section of the rule's `note`.
*   Create exceptions for known backup operations, software updates, and data archiving processes that may trigger false positives, referencing the "False positive analysis" section of the rule's `note`.
*   Implement additional monitoring on similar devices and network segments to detect any further anomalous data transfer activities, based on the rule's description and "Response and remediation" section of the `note`.
