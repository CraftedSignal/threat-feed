---
title: Unusual Remote File Size Detected by ML
slug: 2026-07-unusual-remote-file-size
description: An Elastic machine learning job detects unusually large file transfers by remote hosts, indicating potential lateral movement or data exfiltration by adversaries who consolidate data into single large files to avoid detection.
date: "2026-07-28T18:07:58Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - lateral-movement
  - collection
  - data-exfiltration
  - machine-learning
  - anomaly-detection
  - elastic-defend
vendors:
  - Elastic
products:
  - Elastic Defend (8.18 and above)
  - Lateral Movement Detection integration
  - Fleet
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: A machine learning job has detected an unusually high file size shared by a remote host indicating potential lateral movement activity.
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
    evidence: Attackers might choose to bundle data into a single large file transfer.
    confidence_band: med
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1039
    technique_name: Data from Network Shared Drive
    evidence: One of the primary goals of attackers after gaining access to a network is to locate and exfiltrate valuable information. Instead of multiple small transfers that can raise alarms, attackers might choose to bundle data into a single large file transfer.
    confidence_band: med
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/lmd
  - https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration
  - https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security
---

The Elastic machine learning rule, "Unusual Remote File Size", identifies potential lateral movement or data exfiltration by flagging abnormally large file sizes transferred from remote hosts. Attackers often consolidate data into single large files to circumvent detection mechanisms that might trigger on multiple smaller transfers. This rule, part of the Lateral Movement Detection integration, leverages Elastic's Anomaly Detection feature to analyze file and Windows RDP process events, requiring the `host.ip` field to be populated. For Elastic Defend versions 8.18 and above, explicit configuration is needed to enable host IP collection. The integration also requires the installation of preconfigured anomaly detection jobs within Fleet. This detection helps defenders identify suspicious network activity that could indicate an adversary moving within the network or preparing to exfiltrate data.

## Impact

If attackers successfully transfer unusually large files for lateral movement or data exfiltration, organizations face significant risks including the theft of sensitive information, establishment of further persistence within the network, and potential system compromise. The consolidation of data into large files allows adversaries to achieve their objectives with a higher likelihood of evading traditional security alerts. This could lead to severe data breaches, regulatory non-compliance fines, and substantial reputational damage for the affected entities.

## Recommendation

* Enable `host.ip` field collection for Elastic Defend events, especially for versions 8.18 and above, by following Elastic's official configuration steps outlined in their helper guide.
* Install the Lateral Movement Detection integration assets in Kibana, ensuring all prerequisites are met and preconfigured anomaly detection jobs are added as described in the `setup` section.
* Review the alert details for `Unusual Remote File Size` to identify specific remote hosts and file sizes involved in detected anomalies.
* Analyze network logs to trace the origin and destination of any suspicious large file transfers.
* Implement network segmentation to limit lateral movement capabilities within the environment if a detected anomaly indicates malicious activity.
* Conduct thorough analysis of the contents and origin of unusually large file transfers to determine if sensitive data was involved and reset credentials for any associated compromised accounts.
