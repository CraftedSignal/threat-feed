---
title: Unusual Remote File Size Indicating Lateral Movement
slug: 2024-04-30-unusual-remote-file-size
description: A machine learning job has detected an unusually high file size shared by a remote host, indicating potential lateral movement as attackers bundle data into a single large file transfer to evade detection when exfiltrating valuable information.
date: "2024-04-30T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - lateral-movement
  - data-exfiltration
  - machine-learning
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1039
    technique_name: Data from Network Shared Drive
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/lmd
  - https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration
  - https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security
rules:
  - title: High File Size Transfer via RDP
    description: Detects unusually high file sizes transferred via RDP, potentially indicating lateral movement and data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1570
    data_sources:
      - network_connection
      - windows
  - title: Suspiciously Large File Creation in User Directory
    description: Detects the creation of a suspiciously large file within a user's directory, which may precede a remote transfer.
    platform: sigma
    severity: low
    tactics:
      - collection
    techniques:
      - T1039
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This detection leverages machine learning to identify unusual remote file sizes, a tactic often used during lateral movement. After gaining initial access, adversaries frequently aim to locate and exfiltrate valuable data. To avoid raising alarms with numerous small transfers, they may consolidate data into a single large file. This rule, built upon the Elastic Lateral Movement Detection integration, specifically uses the `lmd_high_file_size_remote_file_transfer_ea` machine learning job. The integration requires the `host.ip` field to be populated and Elastic Defend to be properly configured. This detection is critical for organizations seeking to identify and prevent data exfiltration attempts early in the attack lifecycle. The integration assets must be installed and file and Windows RDP process events collected by Elastic Defend.

## Attack Chain

1.  Initial Access: An attacker gains access to a host within the network, potentially through compromised credentials or exploitation of a vulnerability.
2.  Discovery: The attacker performs reconnaissance to identify valuable data stores, network shares, and potential exfiltration targets.
3.  Collection: The attacker gathers sensitive data from various sources within the compromised network. This data could include documents, databases, or other confidential information.
4.  Data Consolidation: To avoid detection, the attacker bundles the collected data into a single, large file. This could involve archiving, compression, or other methods of aggregation.
5.  Lateral Tool Transfer: The attacker uses remote services or tools to transfer the large file to a remote host within the network (T1570).
6.  Exfiltration Preparation: The attacker stages the large file on the remote host, preparing it for exfiltration outside the network.
7.  Exfiltration: The attacker initiates the transfer of the large file from the compromised network to an external destination, potentially using protocols like RDP.
8.  Cleanup: The attacker attempts to remove traces of the activity, such as deleting temporary files or logs, to avoid detection.

## Impact

A successful attack can lead to the exfiltration of sensitive data, potentially resulting in financial loss, reputational damage, and legal liabilities. The detection of unusual remote file sizes can help organizations identify and prevent data exfiltration attempts before they cause significant harm. Depending on the sensitivity of the exfiltrated data, the impact could range from minor inconvenience to a major security breach affecting thousands of individuals or customers.

## Recommendation

*   Ensure the `host.ip` field is populated as required by the rule. For Elastic Defend versions 8.18 and above, verify that host IP collection is enabled following the provided [helper guide](https://www.elastic.co/docs/solutions/security/configure-elastic-defend/configure-data-volume-for-elastic-endpoint#host-fields).
*   Install the Lateral Movement Detection integration assets, including the `lmd_high_file_size_remote_file_transfer_ea` machine learning job. Follow the setup instructions detailed in the [documentation](https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html).
*   Review and tune the anomaly threshold (`anomaly_threshold = 70`) of the machine learning job based on your environment's baseline to reduce false positives.
*   Implement network segmentation to limit lateral movement, as suggested in the "Response and remediation" section of the rule documentation.
*   Enhance monitoring and logging for unusual file transfer activities and remote access attempts as stated in the rule documentation.
