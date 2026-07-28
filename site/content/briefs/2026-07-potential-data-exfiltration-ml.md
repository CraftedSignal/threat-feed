---
title: Potential Data Exfiltration Activity to an Unusual ISO Code Detected via Machine Learning
slug: 2026-07-potential-data-exfiltration-ml
description: Elastic's machine learning job detects potential data exfiltration by identifying anomalous network traffic patterns to unusual geographical locations, leveraging network and file event data collected by integrations like Elastic Defend and Network Packet Capture.
date: "2026-07-28T18:01:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - data-exfiltration
  - machine-learning
  - elastic-defend
  - network-traffic
  - anomaly-detection
  - threat-detection
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: A machine learning job has detected data exfiltration to a particular geo-location (by region name). Data transfers to geo-locations that are outside the normal traffic patterns of an organization could indicate exfiltration over command and control channels.
    confidence_band: high
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/ded
  - https://www.elastic.co/blog/detect-data-exfiltration-activity-with-kibanas-new-integration
---

This threat brief describes a machine learning (ML) based detection designed by Elastic to identify potential data exfiltration activity. The ML job, `ded_high_sent_bytes_destination_geo_country_iso_code_ea`, analyzes network traffic patterns to detect unusually large data transfers to specific geographic locations (ISO codes) that deviate from an organization's normal traffic baselines. Adversaries often exfiltrate sensitive data via command and control (C2) channels to destinations not typically accessed by the compromised network. The detection leverages network and file events gathered by Elastic integrations such as Elastic Defend and Network Packet Capture. This rule is crucial for early identification of unauthorized data egress, which can precede significant data breaches. The system requires the Data Exfiltration Detection integration and Elastic's anomaly detection feature, operating on a 15-minute interval to monitor for these deviations.

## Attack Chain

The provided source describes a machine learning detection rule for data exfiltration, rather than a specific attack chain. The detection triggers when an adversary has already established a presence within a network and is attempting to transfer sensitive data to external, unusual geographic locations, likely over command and control channels. This detection focuses on the final stages of data egress.

## Impact

Successful data exfiltration leads to a data breach, resulting in the loss of sensitive information such as intellectual property, customer data, financial records, or credentials. This can incur significant financial damages from regulatory fines (e.g., GDPR, HIPAA), legal liabilities, remediation costs, and reputational damage. Depending on the nature of the exfiltrated data, it can lead to competitive disadvantage, blackmail, or further cyberattacks. The detection aims to prevent or limit the scope of such breaches by flagging suspicious outbound data flows to unusual destinations, which could indicate a successful compromise and ongoing data theft.

## Recommendation

* Enable network and file event collection from Elastic Defend and Network Packet Capture integrations to feed the anomaly detection job.
* Install and configure the Data Exfiltration Detection integration within Elastic Kibana, ensuring the preconfigured anomaly detection jobs are added.
* Review the generated ML alerts for `e1db8899-97c1-4851-8993-3a3265353601` to identify unusual ISO codes and geo-locations involved in data transfers.
* Establish baselines for legitimate data transfers to international locations and cloud services, and create exceptions for known benign activities to reduce false positives, as mentioned in the rule's `false positive analysis`.
* Block the identified IP addresses or domains associated with unusual ISO codes in firewalls and intrusion prevention systems upon confirmation of malicious activity.
