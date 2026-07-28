---
title: Unusual Process Writing Data to an External Device Detected by Machine Learning
slug: 2026-07-unusual-process-external-device
description: Elastic's Data Exfiltration Detection integration leverages machine learning to identify rare processes writing data to external devices, indicating potential data exfiltration by adversaries using benign-looking processes.
date: "2026-07-28T18:05:39Z"
lastmod: "2026-07-28T18:36:13Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - exfiltration
  - machine-learning
  - elastic-defend
  - endpoint
  - lateral-movement
  - rdp
  - anomaly-detection
  - privilege-escalation
  - linux
  - behavioral-detection
  - elastic
  - discovery
  - reconnaissance
  - threat-detection
  - initial-access
  - credential-access
  - auditd-manager
  - host-based-detection
  - data-exfiltration
  - ddos
  - malware
  - system-compromise
  - elastic-security
  - anomaly_detection
  - network_denial
  - firewall
  - machine_learning
  - threat_detection
vendors:
  - Elastic
  - Microsoft
products:
  - Elastic Defend
  - Data Exfiltration Detection integration
  - Fleet
  - Kibana
  - Windows RDP
  - Elastic Stack >= 9.4.0
  - Lateral Movement Detection integration
  - Elastic Security
  - Sysmon Linux
  - Privileged Access Detection integration
  - Auditd Manager
  - Elastic Agent
  - System
  - Windows
  - Network Packet Capture
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1052
    technique_name: Exfiltration Over Physical Medium
    evidence: A machine learning job has detected a rare process writing data to an external device. Malicious actors often use benign-looking processes to mask their data exfiltration activities.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: An RDP session at an unusual time could be followed by other suspicious activities, so catching this is a good first step in detecting a larger attack.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Remote Desktop Protocol (RDP) enables remote access to systems, crucial for IT management but also a target for adversaries seeking unauthorized access. Attackers exploit RDP by initiating sessions at odd hours to avoid detection.
    confidence_band: med
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries often exploit valid accounts to escalate privileges and access sensitive systems.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: A machine learning job has detected an increase in the execution of privileged commands by a user, suggesting potential privileged access activity.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Connections Discovery
    evidence: A compromised account may be used by a threat actor to engage in system network connection discovery in order to increase their understanding of connected services and systems.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A machine learning job detected a user logging in from an IP address that is unusual for the user. This can be due to credentialed access via a compromised account when the user and the threat actor are in different locations.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: This can be due to a range of security issues, such as a compromised system, DDoS attacks, malware infections, privilege escalation, or data exfiltration.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: This can be due to a range of security issues, such as a compromised system, DDoS attacks, malware infections, privilege escalation, or data exfiltration.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: This can be due to a range of security issues, such as a compromised system, DDoS attacks, malware infections, privilege escalation, or data exfiltration.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This can be due to a range of security issues, such as a compromised system, DDoS attacks, malware infections, privilege escalation, or data exfiltration.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Unsuccessful attempts at network transit, in order to connect to command-and-control (C2)... may produce a burst of failed connections.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
    evidence: This could also be due to unusually large amounts of reconnaissance or enumeration traffic.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: This could also be due to unusually large amounts of reconnaissance or enumeration traffic.
    confidence_band: high
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1590
    technique_name: Gather Victim Network Information
    evidence: This could also be due to unusually large amounts of reconnaissance or enumeration traffic.
    confidence_band: high
  - tactic_id: TA0043
    tactic_name: Reconnaissance
    technique_id: T1595
    technique_name: Active Scanning
    evidence: This could also be due to unusually large amounts of reconnaissance or enumeration traffic.
    confidence_band: high
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/ded
  - https://www.elastic.co/blog/detect-data-exfiltration-activity-with-kibanas-new-integration
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/lmd/lateral_movement_ml_rare_remote_file_directory.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/lmd/lateral_movement_ml_spike_in_remote_file_transfers.toml
  - https://docs.elastic.co/en/integrations/lmd
  - https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration
  - https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security
  - https://docs.elastic.co/en/integrations/pad
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/discovery_ml_linux_system_network_connection_discovery.toml
  - https://attack.mitre.org/techniques/T1049/
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/initial_access_ml_auth_rare_source_ip_for_a_user.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/initial_access_ml_auth_rare_user_logon.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/initial_access_ml_linux_anomalous_user_name.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/ml_high_count_events_for_a_host_name.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/ml_high_count_network_denies.toml
updates:
  - at: "2026-07-28T18:31:02Z"
    level: L1
    summary: 'merged source coverage: Unusual Linux Network Connection Discovery Detected by Elastic ML'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/ml/discovery_ml_linux_system_network_connection_discovery.toml
  - at: "2026-07-28T18:33:07Z"
    level: L1
    summary: 'merged source coverage: Unusual Source IP for User Logon Detection by Elastic ML'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/ml/initial_access_ml_auth_rare_source_ip_for_a_user.toml
  - at: "2026-07-28T18:33:56Z"
    level: L1
    summary: 'merged source coverage: Detection of Unusual Linux Username Activity via Machine Learning'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/ml/initial_access_ml_linux_anomalous_user_name.toml
  - at: "2026-07-28T18:35:09Z"
    level: L1
    summary: 'merged source coverage: Spike in Host-Based Traffic Detected by Machine Learning'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/ml/ml_high_count_events_for_a_host_name.toml
  - at: "2026-07-28T18:36:13Z"
    level: L1
    summary: 'merged source coverage: Spike in Firewall Denies Machine Learning Rule Detection'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/ml/ml_high_count_network_denies.toml
---

Elastic has released a machine learning-based detection rule designed to identify potential data exfiltration attempts. This rule, part of the Data Exfiltration Detection integration, focuses on detecting unusual or rare processes that write data to external devices. Adversaries frequently use seemingly legitimate processes to mask their data exfiltration activities, making such abnormal behavior a strong indicator of compromise. The detection relies on Elastic's Anomaly Detection feature, analyzing network and file events collected via integrations like Elastic Defend and Network Packet Capture. This capability, available for Elastic Stack version 9.4.0 and higher, helps defenders identify deviations from typical process behavior, flagging potential threats where sensitive data might be transferred out of the network via an unapproved or suspicious channel.

## Attack Chain

1. An attacker establishes initial access to a target system using various methods (e.g., phishing, exploiting a vulnerability).
2. The attacker deploys or repurposes a benign-looking process on the compromised system.
3. Sensitive data is identified and staged for exfiltration on the local system.
4. The attacker leverages the seemingly legitimate process to write the staged sensitive data to an external device (e.g., USB drive, network share mapped as an external drive).
5. The external device is removed, or the connection is terminated, completing the exfiltration of sensitive information.
6. The unusual behavior of this rare process writing to an external device triggers an anomaly detection by Elastic's ML rule.

## Impact

Successful data exfiltration can lead to severe consequences, including intellectual property theft, compromise of sensitive customer or employee data, regulatory fines due to data breaches, reputational damage, and financial losses. The targeted sectors are broad, as any organization handling valuable data is at risk. While the detection rule identifies a specific activity rather than a campaign, the impact of such exfiltration could range from minor data loss to a catastrophic breach depending on the volume and sensitivity of the data involved.

## Recommendation

* Deploy the Data Exfiltration Detection integration and configure the machine learning job `ded_rare_process_writing_to_external_device_ea` to leverage Elastic's anomaly detection capabilities.
* Ensure Elastic Defend is fully installed and collecting file events on all endpoints, as indicated in the setup instructions.
* When an alert is triggered, investigate the `process name`, `path`, and associated `user account` to determine if the activity is legitimate, as suggested in the investigation guide.
* Review the `external device's details` and the `volume and type of data` being written to identify any sensitive or unusual transfers.
* Use the provided "Investigation Guide" within the rule's note to systematically triage and analyze alerts generated by this rule.
* Create allowlists for legitimate backup processes, data transfer applications, software updates, and IT maintenance activities to reduce false positives, as mentioned in the "False positive analysis" section.
