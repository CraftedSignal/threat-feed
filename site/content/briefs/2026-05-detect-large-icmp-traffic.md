---
title: Detect Large ICMP Traffic
slug: 2026-05-detect-large-icmp-traffic
description: This analytic identifies ICMP traffic to external IP addresses with total bytes greater than 1,000 bytes, leveraging the Network_Traffic data model to detect potential information smuggling, covert communication, or command-and-control (C2) activities.
date: "2026-05-28T18:02:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - network
  - command-and-control
  - icmp
vendors:
  - Palo Alto Networks
  - Cisco
  - Splunk
products:
  - Palo Alto Network Traffic
  - Cisco Secure Access Firewall
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1095
    technique_name: Non-Application Layer Protocol
references:
  - https://github.com/splunk/security_content/blob/main/detections/network/detect_large_icmp_traffic.yml
rules:
  - title: Detect Large ICMP Traffic (Process)
    description: Detects large ICMP traffic initiated by a process, potentially indicating covert communication or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1095
    data_sources:
      - process_creation
      - windows
  - title: Detect Large ICMP Traffic (Network)
    description: Detects large ICMP traffic based on network connection events, potentially indicating covert communication or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1095
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This detection identifies anomalous ICMP traffic indicative of covert communication channels or command-and-control activity. Specifically, it flags ICMP packets exceeding 1,000 bytes in total size destined for external IP addresses. The detection logic relies on the Splunk Network_Traffic data model, providing a normalized view of network events. The analytic focuses on identifying large ICMP packets not explicitly blocked by network defenses. Successful validation of this activity may indicate ICMP tunneling, unauthorized data transfer, or compromised endpoints, necessitating immediate investigation. Originally created in 2020, this analytic has been actively maintained with the latest modification in May 2026.

## Attack Chain

1.  An attacker gains initial access to a compromised host within the network.
2.  The attacker establishes a covert communication channel using ICMP.
3.  The attacker configures the compromised host to send ICMP packets with sizes exceeding 1000 bytes.
4.  Data is encoded and embedded within the ICMP payload.
5.  The compromised host sends the large ICMP packets to an external IP address controlled by the attacker.
6.  Network devices forward the ICMP packets if not blocked by existing firewall rules.
7.  The attacker receives the ICMP packets and extracts the encoded data.
8.  The attacker uses this channel for command execution, data exfiltration, or other malicious activities.

## Impact

Compromised internal hosts may be used to exfiltrate sensitive data or receive command-and-control instructions from external threat actors. Successful ICMP tunneling can bypass traditional security controls, allowing attackers to operate undetected within the network. The impact includes data breaches, intellectual property theft, and potential for further compromise of internal systems. The ability to identify these large ICMP packets can enable security teams to rapidly contain the breach, identify affected assets, and prevent further data loss.

## Recommendation

*   Ensure that network traffic logs from Palo Alto Networks and Cisco Secure Access Firewalls are ingested into Splunk and mapped to the Network_Traffic data model for accurate analysis.
*   Deploy the `Detect Large ICMP Traffic` analytic to your Splunk environment to identify potentially malicious ICMP activity.
*   Tune the `detect_large_icmp_traffic_filter` macro to adjust the byte threshold or add specific IP addresses to an allow list to reduce false positives.
*   Investigate any identified large ICMP packets to determine the source, destination, and purpose of the traffic based on the detection results.
*   Use the drilldown searches provided in the analytic, such as "View the detection results for - \"$src_ip$\" and \"$dest_ip$\"", to further investigate specific events.
*   Monitor for associated risk events for affected source and destination IPs to identify potential lateral movement or data exfiltration.
