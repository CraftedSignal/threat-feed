---
title: Potential Data Exfiltration Activity to an Unusual Destination Port
slug: 2026-07-elastic-ml-exfil-port
description: A machine learning job by Elastic detects potential data exfiltration by identifying anomalous network traffic patterns where high bytes are sent to an unusual destination port, suggesting data is being exfiltrated via command and control channels.
date: "2026-07-28T18:02:48Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - data-exfiltration
  - machine-learning
  - network-security
  - elastic-defend
  - network-packet-capture
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: A machine learning job has detected data exfiltration to a particular destination port. Data transfer patterns that are outside the normal traffic patterns of an organization could indicate exfiltration over command and control channels.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1571
    technique_name: Non-Standard Port
    evidence: Data transfer patterns that are outside the normal traffic patterns of an organization could indicate exfiltration over command and control channels.
    confidence_band: high
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/ded
  - https://www.elastic.co/blog/detect-data-exfiltration-activity-with-kibanas-new-integration
---

This brief details a machine learning-based detection rule developed by Elastic, designed to identify potential data exfiltration activities within an organization's network. The rule, titled "Potential Data Exfiltration Activity to an Unusual Destination Port," leverages Elastic's anomaly detection capabilities to flag instances where an unusual volume of data (high bytes) is transferred to destination ports that deviate from established normal traffic patterns. This behavior is indicative of adversaries attempting to exfiltrate sensitive information over command and control (C2) channels. The detection relies on the Data Exfiltration Detection integration, requiring network and file events collected by Elastic Defend or Network Packet Capture integrations. While not tied to a specific threat actor or campaign, this rule helps defenders identify stealthy exfiltration attempts that might bypass traditional signature-based detections by recognizing anomalous network behavior, thereby providing an early warning system against sophisticated data theft operations.

## Attack Chain

(No specific attack chain is provided as this brief describes a generic machine learning detection rule, not a specific incident or exploitation scenario.)

## Impact

Successful data exfiltration, which this machine learning rule aims to detect, can result in severe consequences for an organization. This includes the loss of sensitive intellectual property, customer data, and financial records, leading to significant financial damages through regulatory fines, legal liabilities, and direct costs associated with incident response. Beyond monetary losses, data breaches severely damage an organization's reputation and customer trust. Early detection of anomalous data transfers to unusual ports, as identified by this rule, is crucial to mitigate these impacts by enabling timely intervention before large-scale data theft occurs. The rule acts as a proactive measure against stealthy exfiltration methods often employed by sophisticated threat actors to maintain persistence and siphon data without immediate detection.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
* Install the Elastic Data Exfiltration Detection integration and configure preconfigured anomaly detection jobs as described in the `setup` instructions within the rule.
* Ensure network events are collected from endpoints via `Elastic Defend` and network capture via `Network Packet Capture` integrations to feed the machine learning job with essential telemetry.
* Upon detection, investigate alerts by reviewing `network_traffic` logs to identify the source IP, destination port, and data volume, correlating findings with other security alerts for a comprehensive view.
* Identify and document legitimate internal applications and external services that utilize non-standard ports to minimize false positives and improve the accuracy of the machine learning model.
* Review and update firewall and intrusion detection/prevention system rules based on findings from anomalous traffic to block further unauthorized data transfers.
