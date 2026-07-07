---
title: IPSEC NAT Traversal Port Activity Used for Command and Control
slug: 2026-07-ipsec-nat-traversal-c2
description: A detection rule identifies suspicious outbound IPSEC NAT Traversal (NAT-T) tunnels, characterized by UDP traffic where both source and destination ports are 4500, originating from an internal host to an external destination, a technique frequently abused by threat actors to establish covert command and control channels or exfiltrate data while evading network defenses.
date: "2026-07-03T15:52:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - network
  - vpn
  - exfiltration
  - protocol-tunneling
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1095
    technique_name: Non-Application Layer Protocol
    evidence: This rule detects... this technique is also used by threat actors to tunnel command and control or exfiltration traffic over the Internet to avoid detection.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: This rule detects... this technique is also used by threat actors to tunnel command and control or exfiltration traffic over the Internet to avoid detection.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
    evidence: IPSEC is a VPN technology that allows one system to talk to another using encrypted tunnels... This may be common on your network, but this technique is also used by threat actors to tunnel command and control or exfiltration traffic over the Internet to avoid detection.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/network/command_and_control_nat_traversal_port_activity.toml
rules:
  - title: IPSEC NAT Traversal Port Activity
    description: Detects outbound IPSEC NAT Traversal (NAT-T) tunnels from an internal host to an external destination, characterized by UDP traffic where both source and destination ports are 4500. This technique is often used by threat actors for command and control or data exfiltration.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1095
      - T1572
      - T1573
    data_sources:
      - network_connection
rules_count: 1
---

This brief focuses on the detection of outbound IPSEC NAT Traversal (NAT-T) tunnels, a legitimate VPN technology that enables secure communication across Network Address Translation (NAT) devices by encapsulating IPSEC Encapsulating Security Payload (ESP) traffic within UDP, typically floating to UDP port 4500 for the tunnel data channel. While essential for valid encrypted communications, this technique is also widely exploited by various threat actors to establish covert command and control (C2) channels, facilitate data exfiltration, or maintain persistent access. By mimicking benign VPN traffic, adversaries attempt to bypass traditional network defenses that might otherwise flag unusual outbound connections. This detection rule identifies this specific network signature – UDP traffic with both source and destination ports set to 4500, originating from an internal network segment to an external, routable IP address – to flag potential malicious tunneling attempts that warrant further investigation.

## Impact

If successfully exploited by threat actors for malicious purposes, the use of IPSEC NAT-T tunnels can lead to the establishment of covert command and control (C2) channels, allowing attackers to remotely control compromised systems within the network. This can enable subsequent stages of an attack, such as data exfiltration, deployment of additional malware, lateral movement, or ransomware deployment, all while remaining hidden from common network security monitoring due to the encrypted nature and the abuse of a legitimate protocol. The impact can range from intellectual property theft and loss of sensitive data to significant operational disruption and financial damage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM/detection platform and configure network logging to capture UDP traffic including source/destination IP, ports, and protocol.
*   Investigate alerts by reviewing the source and destination IP addresses involved; determine if they correspond to known or expected legitimate VPN services or devices as described in the `falsepositives` section of the rule.
*   Correlate detected NAT-T activity with other security events and endpoint logs for the originating host to identify any suspicious processes or unusual network connections that may indicate a compromise.
*   Whitelist known and authorized site-to-site or client VPN endpoints that legitimately use IPSEC NAT Traversal on UDP port 4500 to reduce false positives, as detailed in the `falsepositives` section.
*   Block suspicious external destination IP addresses observed in alerts at the network perimeter to prevent further communication with potential threat actor infrastructure.
