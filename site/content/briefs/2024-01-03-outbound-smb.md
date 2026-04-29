---
title: Outbound SMB Traffic Detection
slug: 2024-01-03-outbound-smb
description: This analytic detects outbound SMB connections from internal hosts to external servers, potentially indicating lateral movement and credential theft attempts.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - network
  - smb
  - lateral-movement
  - privilege-escalation
vendors:
  - Cisco
  - Splunk
products:
  - Secure Firewall Threat Defense
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Secure Access Firewall
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://github.com/splunk/security_content/blob/main/detections/network/detect_outbound_smb_traffic.yml
rules:
  - title: Outbound SMB Traffic Detected
    description: Detects SMB traffic originating from internal networks destined for external IP addresses, which could indicate unauthorized data access or lateral movement.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - network_connection
      - cisco
  - title: Outbound SMB Traffic - Firewall Deny
    description: Detects firewall events where SMB traffic from internal to external destinations is denied.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - firewall
      - cisco
rules_count: 2
---

This detection identifies outbound Server Message Block (SMB) traffic from internal hosts to external servers. The activity is identified by monitoring network traffic for SMB requests directed towards the Internet, an unusual occurrence in standard operations. This analytic is crucial for Security Operations Centers (SOCs) as it can signal an attacker's attempt to retrieve credential hashes via compromised internal systems, a critical step in lateral movement and privilege escalation. The source mentions specific relevance to "Hidden Cobra Malware", "DHS Report TA18-074A", and "NOBELIUM Group", suggesting possible connections to these threat actors or campaigns.

## Attack Chain

1. An internal host is compromised through an initial access vector (e.g., phishing, exploit).
2. The attacker attempts to enumerate network resources accessible from the compromised host.
3. The attacker leverages SMB to connect to external servers, typically on ports 139 or 445.
4. The SMB connection attempts to authenticate or negotiate with the external server.
5. The attacker may attempt to exploit vulnerabilities in the SMB protocol or server.
6. The attacker captures or relays credential hashes transmitted over the SMB connection.
7. The attacker uses the captured credentials to move laterally to other systems or escalate privileges.
8. The attacker achieves their final objective, such as data exfiltration or system compromise.

## Impact

Successful exploitation of outbound SMB traffic can lead to unauthorized access to sensitive data and full system compromise. Lateral movement and privilege escalation are key goals. Confirmed malicious SMB traffic could enable attackers to move through the network, potentially impacting numerous systems and leading to significant data breaches. While the number of victims isn't specified, the detection's relevance to known threat actors suggests potentially widespread impact.

## Recommendation

*   Deploy the Sigma rule `Outbound SMB Traffic Detected` to your SIEM and tune it for your environment, using the provided positive and negative test cases to ensure accurate detection.
*   Investigate and block any detected outbound SMB connections that are not explicitly authorized by legitimate business needs (reference `detect_outbound_smb_traffic_filter` macro in the original search).
*   Implement network segmentation to restrict internal hosts from directly accessing external SMB services.
*   Enforce strong password policies and multi-factor authentication to mitigate the impact of credential theft.
*   Categorize internal CIDR blocks as `internal` in your asset management system to reduce false positives (reference "known_false_positives" section).
*   Consider blocking external communications of all SMB versions and related protocols at the network boundary.
