---
title: Windows Remote Desktop Network Bruteforce Attempt
slug: 2024-01-rdp-bruteforce
description: This detection identifies potential RDP brute force attacks by monitoring network traffic for RDP application activity by detecting source IPs that have made more than 10 connection attempts to the same RDP port on a host within a one-hour window.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rdp
  - bruteforce
  - credential-access
  - windows
  - network
vendors:
  - Cisco
  - Splunk
products:
  - Secure Access Firewall
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://www.zscaler.com/blogs/security-research/ransomware-delivered-using-rdp-brute-force-attack
  - https://www.reliaquest.com/blog/rdp-brute-force-attacks/
rules:
  - title: RDP Bruteforce via Network Traffic
    description: Detects potential RDP brute force attacks by monitoring network connections and identifying source IPs making multiple connection attempts to the same destination RDP port within a short timeframe.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - network_connection
      - windows
  - title: Sysmon RDP Bruteforce Detection
    description: Detects RDP brute force attempts using Sysmon Event ID 3 by monitoring network connections and identifying source IPs making multiple connection attempts to the same destination RDP port within a short timeframe.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This analytic identifies potential Remote Desktop Protocol (RDP) brute force attacks by monitoring network traffic for RDP application activity. It detects potential RDP brute force attacks by identifying source IPs that have made more than 10 connection attempts to the same RDP port on a host within a one-hour window. The results are presented in a table that includes the source and destination IPs, destination port, number of attempts, and the times of the first and last connection attempts, helping to prioritize IPs based on the intensity of activity. This activity can lead to account compromise and potential ransomware deployment.

## Attack Chain

1. The attacker scans the network to identify systems with open RDP ports (TCP 3389).
2. The attacker initiates multiple RDP connection attempts to a target host, using a list of common usernames and passwords or compromised credentials.
3. The firewall logs each connection attempt, recording the source and destination IPs, ports, and timestamps.
4. Sysmon logs the network connections with Event ID 3.
5. The attacker continues to attempt connections, typically exceeding 10 attempts within an hour.
6. Upon successful authentication, the attacker gains unauthorized access to the target system.
7. The attacker may then install malware, move laterally, or exfiltrate sensitive data.
8. The attacker might deploy ransomware like SamSam or Ryuk, as referenced in external reports.

## Impact

Successful RDP brute force attacks can lead to unauthorized access to systems, data breaches, malware infections, and ransomware deployment. Compromised systems can be used as a staging point for further attacks within the network. The references indicate that ransomware attacks have been delivered using RDP brute-force techniques.

## Recommendation

*   Ensure network traffic data is populating the Network_Traffic data model to enable the provided search query.
*   Deploy the Sigma rule `RDP Bruteforce via Network Traffic` to detect brute force attempts based on network connection patterns.
*   Adjust the count and duration thresholds in the detection query to tune the sensitivity for your environment.
*   Investigate source IPs identified by the detection rule as potential attackers.
*   Monitor Sysmon EventID 3 for network connections to detect RDP brute-force attempts.
*   Review the referenced Zscaler and ReliaQuest articles for additional context and mitigation strategies.
