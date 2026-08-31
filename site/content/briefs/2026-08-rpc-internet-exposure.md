---
title: Detection of Unauthorized RPC Traffic to the Internet
slug: 2026-08-rpc-internet-exposure
description: This brief details detection logic for identifying potentially malicious RPC traffic originating from internal segments toward external networks, a common vector for initial access and lateral movement.
date: "2026-08-31T07:05:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - network-security
  - rpc
  - initial-access
  - lateral-movement
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It should almost never be directly exposed to the Internet, as it is frequently targeted and exploited by threat actors as an initial access or backdoor vector.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: RPC is commonly used by system administrators to remotely control a system for maintenance or to use shared resources.
    confidence_band: high
rules:
  - title: Detect Unauthorized RPC Traffic to the Internet
    description: Detects RPC traffic (port 135 or DCE/RPC) originating from internal RFC 1918 addresses to external internet-routable addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - lateral_movement
    techniques:
      - T1021.003
      - T1190
    data_sources:
      - network_connection
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the RPC-to-internet detection rule and tune against known-legitimate management traffic.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides detection query and logic.
  hunt_leads:
    - lead: Search network logs for any outbound traffic on port 135 over the last 30 days.
      technique_id: T1021.003
      data_needed:
        - Network flow logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies RPC to internet as a high-risk activity.
  mitigation_plan:
    - priority: immediate
      action: Implement strict egress filtering at the network boundary for TCP port 135.
      owner: IT Operations
      addresses: RPC internet exposure
      evidence: Source advises against direct internet exposure of RPC services.
---

Remote Procedure Call (RPC) is a fundamental protocol used for system administration, resource sharing, and cross-system management. While essential for internal operations, RPC services (particularly on port 135) should never be directly exposed to the public Internet. Threat actors frequently scan for and target exposed RPC interfaces to achieve initial access, deploy backdoors, or facilitate lateral movement within compromised environments. This detection focuses on identifying traffic originating from internal IP ranges (RFC 1918) that is destined for external, non-private IP space. Defenders should treat such telemetry as high-fidelity evidence of potential misconfiguration or active unauthorized remote access.

## Attack Chain

1. Attacker performs reconnaissance to identify exposed RPC endpoints (e.g., port 135) on the target organization's internet-facing assets.
2. Attacker interacts with the RPC endpoint to identify services, versions, or potential vulnerabilities present on the host.
3. Attacker leverages a remote exploitation technique against the service (e.g., buffer overflow or deserialization flaw).
4. Upon successful exploitation, the attacker executes arbitrary commands or uploads a web shell/backdoor.
5. The compromised system initiates an outbound RPC connection to an attacker-controlled listener or C2 node to finalize the connection.
6. Attacker utilizes the established connection for lateral movement, credential theft, or exfiltration of sensitive internal data.

## Impact

Successful exploitation of exposed RPC services can result in full system compromise, unauthorized access to sensitive data, and the establishment of persistent backdoors. These attacks facilitate further network intrusion, potentially impacting an entire organization's infrastructure by enabling lateral movement across sensitive segments.

## Recommendation

Prioritize the investigation of any internal host generating RPC traffic (TCP port 135 or DCE/RPC traffic) directed toward external IP space.
- Implement the provided Sigma rule to flag anomalous RPC traffic patterns in network security logs.
- Review network egress filtering policies to explicitly block inbound and outbound traffic on RPC-associated ports at the network perimeter.
- Isolate systems identified by this detection and investigate for unauthorized installed services or modifications.
- Validate that all internal services requiring RPC for cross-system management are configured to only communicate over authorized internal VPNs or secure management subnets.
