---
title: Detecting Lateral Movement via RDP Connection Spikes
slug: 2026-07-rdp-lateral-movement-spike
description: Elastic Security's machine learning rule detects a high count of source IP addresses establishing Remote Desktop Protocol (RDP) connections with a single destination IP, indicating potential lateral movement attempts by threat actors using multiple compromised systems for persistence and redundancy.
date: "2026-07-28T18:10:23Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - lateral-movement
  - rdp
  - machine-learning
  - elastic-security
  - anomaly-detection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: A machine learning job has detected a high count of source IPs establishing an RDP connection with a single destination IP.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Attackers might use multiple compromised systems to attack a target to ensure redundancy in case a source IP gets detected and blocked.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/lmd/lateral_movement_ml_spike_in_connections_to_a_destination_ip.toml
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/lmd
  - https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration
  - https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security
---

This brief describes a machine learning rule developed by Elastic Security designed to detect lateral movement within an environment. The rule identifies anomalous spikes in the number of distinct source IP addresses initiating Remote Desktop Protocol (RDP) connections to a single destination IP. Threat actors frequently leverage RDP for lateral movement after gaining initial access to an environment. They may use multiple compromised systems to establish RDP connections to a target, ensuring redundancy and persistence even if some source IPs are detected and blocked. The rule, identified by `lmd_high_rdp_distinct_count_source_ip_for_destination_ea`, is part of the Elastic Lateral Movement Detection (LMD) integration and requires `host.ip` data collected by Elastic Defend. This detection capability is crucial for identifying early signs of sophisticated adversaries attempting to expand their foothold.

## Attack Chain

1. **Initial Access & Credential Compromise**: The attacker gains initial access to a system within the network, often through phishing, exploiting a vulnerable service, or brute-forcing credentials, leading to the compromise of user or service account credentials.
2. **Internal Reconnaissance**: The attacker performs internal network reconnaissance to identify accessible hosts, particularly those with RDP enabled, and high-value targets. This often includes querying Active Directory or scanning subnets.
3. **Establish Multiple Footholds**: To ensure persistence and redundancy, the attacker compromises several additional internal systems, installing backdoors or gaining control over multiple user accounts.
4. **Coordinated RDP Connection Attempts**: From these various compromised internal systems, the attacker initiates a high volume of RDP connection attempts directed at a single, high-value target system.
5. **Successful RDP Session Establishment**: One or more of these RDP attempts succeed, granting the attacker interactive remote access to the target system.
6. **Action on Objectives**: Using the RDP session, the attacker executes commands, deploys additional tools, exfiltrates data, or moves further into the network to achieve their final objectives, such as data exfiltration or ransomware deployment.

## Impact

A successful lateral movement attack via RDP can lead to significant compromise of an organization's internal network. Attackers can gain access to sensitive data, deploy ransomware across multiple systems, disrupt critical business operations, and establish long-term persistence within the environment, making remediation efforts more complex and costly. While specific victim counts are not available for this detection rule, the general impact of unmitigated lateral movement can range from data breaches and financial losses to severe reputational damage and regulatory fines.

## Recommendation

* Ensure `host.ip` collection is enabled in your Elastic Defend configuration by following the steps in the Elastic helper guide to activate the necessary host fields for detection.
* Install the Elastic Lateral Movement Detection (LMD) integration to leverage its anomaly detection capabilities.
* Deploy the `lmd_high_rdp_distinct_count_source_ip_for_destination_ea` machine learning job as detailed in the LMD integration setup instructions.
* Investigate all alerts generated by the `Spike in Number of Connections Made to a Destination IP` rule, analyzing source IPs, destination IP, user accounts, and connection timings to distinguish malicious activity from legitimate administrative tasks or automated tools.
