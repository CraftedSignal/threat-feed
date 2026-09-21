---
title: Detection of Internal Horizontal Port Scanning Activity
slug: 2026-09-internal-horizontal-port-scan
description: Detection logic identifying internal hosts performing broad network reconnaissance by scanning 250+ unique IP addresses across NMAP's top 20 common ports.
date: "2026-09-21T19:13:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - network-discovery
  - internal-scanning
  - nmap
vendors:
  - Amazon
  - Cisco
products:
  - AWS CloudWatch
  - Cisco Secure Firewall Threat Defense
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Horizontal port scans from internal hosts can indicate reconnaissance or scanning activities, potentially signaling malicious intent.
    confidence_band: high
rules:
  - title: Detect Internal Horizontal Port Scan NMAP Top 20
    description: Detects internal hosts scanning 250 or more unique destination IP addresses across common NMAP target ports within a one-hour period.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1046
    data_sources:
      - network_connection
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable network telemetry ingestion and tune thresholds based on environment baseline
      owner: Detection Engineering
      due: 7d
      evidence: Requires Cisco Secure Firewall or AWS VPC Flow ingestion
  hunt_leads:
    - lead: Search for high-volume connections from internal IPs to sensitive subnets
      technique_id: T1046
      data_needed:
        - Network connection logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Scan detection logic mapping
  mitigation_plan:
    - priority: medium_term
      action: Implement network segmentation to limit lateral scan spread
      owner: IT Operations
      addresses: T1046
      evidence: Detection logic confirms need for restricted lateral movement
---

This brief outlines a behavioral detection analytic designed to identify internal horizontal port scanning, a common precursor to lateral movement and network exploitation. The detection triggers when an internal host attempts to initiate connections to 250 or more unique destination IP addresses within a one-hour window, specifically targeting ports frequently probed by the NMAP tool (e.g., 21, 22, 23, 25, 53, 80, 443, 3389, 445, 3306). 

This activity is characteristic of network discovery and reconnaissance performed by threat actors or automated worms to map internal network segments, identify accessible services, and locate potential targets for further compromise. Because this detection monitors network telemetry from infrastructure such as VPC flow logs and firewall connection events, it provides visibility into malicious movement that might otherwise bypass endpoint-based security controls. Defenders should use this analytic to flag unauthorized scanning within the internal network segment.

## Impact

Successful internal reconnaissance allows attackers to map internal topology, identify vulnerable services (e.g., SMB/RDP), and stage lateral movement. Unauthorized scanning can lead to data exfiltration, service disruption, and eventual compromise of business-critical assets. Detecting this activity early is essential to interrupting the attack lifecycle before an actor gains persistence or access to sensitive data stores.

## Recommendation

- Deploy the provided Sigma rule to your SIEM/Detection platform to monitor network traffic for high-volume, horizontal port scanning behavior.
- Integrate telemetry from network infrastructure (Cisco Secure Firewall, AWS VPC Flow Logs) into the organization's SIEM to populate the Network_Traffic data model required for this detection.
- Investigate any triggered alerts immediately to determine if the source IP is a legitimate administrative scanner, a misconfigured automation, or a compromised asset performing unauthorized reconnaissance.
- Review network access control lists (ACLs) and firewall policies to restrict unnecessary inter-zone communication, especially for sensitive internal segments.
