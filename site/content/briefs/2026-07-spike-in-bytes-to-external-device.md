---
title: Detecting Anomalous Data Transfer to External Devices
slug: 2026-07-spike-in-bytes-to-external-device
description: Elastic has released a machine learning detection rule designed to identify potential data exfiltration attempts by flagging anomalous spikes in the volume of data written to external devices, indicating illicit data copying or transfer activities by threat actors.
date: "2026-07-28T18:04:37Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - exfiltration
  - data-loss
  - machine-learning
  - elastic-defend
  - endpoint
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1052
    technique_name: Exfiltration Over Physical Medium
    evidence: A machine learning job has detected high bytes of data written to an external device. ... An unusually large amount of data being written is anomalous and can signal illicit data copying or transfer activities.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/ded/exfiltration_ml_high_bytes_written_to_external_device.toml
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/ded
  - https://www.elastic.co/blog/detect-data-exfiltration-activity-with-kibanas-new-integration
---

This brief details a machine learning-based detection rule released by Elastic to identify potential data exfiltration. The rule, titled "Spike in Bytes Sent to an External Device," targets malicious actors attempting to copy or transfer unusually large amounts of data to external physical media, such as USB drives, from an endpoint. These activities are anomalous as they deviate from typical operational data transfer patterns. This detection capability, updated in July 2026, leverages Elastic's Anomaly Detection feature by monitoring file and network events collected via integrations like Elastic Defend. It's crucial for defenders as successful data exfiltration can lead to significant data loss, intellectual property theft, and regulatory non-compliance. The rule specifically detects deviations from established baselines in bytes written, making it an early indicator of illicit data movement.

## Impact

Successful data exfiltration, as identified by this detection rule, leads to the unauthorized removal of sensitive information from an organization's control. This can result in significant financial losses, competitive disadvantage due to intellectual property theft, reputational damage, and severe legal repercussions under data protection regulations. The number of potential victims and affected sectors is broad, as any organization handling sensitive data is a target. If exfiltration goes undetected, attackers can monetize stolen data on dark web markets, use it for further attacks (e.g., blackmail), or compromise operational continuity.

## Recommendation

* Install the Data Exfiltration Detection integration assets in Kibana, including configuring preconfigured anomaly detection jobs, to enable this machine learning rule.
* Ensure Elastic Defend is installed and configured to collect file events on all endpoints to provide necessary telemetry for the ML rule.
* Review the rule's `machine_learning_job_id` `ded_high_bytes_written_to_external_device_ea` to understand the ML model and its parameters.
* Correlate alerts from this rule with user activity logs to validate if detected data transfers align with known or authorized user actions.
* Implement policies to restrict unauthorized use of external devices and enforce data transfer policies to minimize exfiltration vectors.
* Analyze `falsepositives` related to regular backups, software updates, data archiving, media content creation, or legitimate business transfers to tune the rule and create necessary exclusions.
