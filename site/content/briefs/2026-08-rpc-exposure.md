---
title: Exposure of Remote Procedure Call Services to the Internet
slug: 2026-08-rpc-exposure
description: Publicly accessible Remote Procedure Call (RPC) services on TCP port 135 facilitate initial access and backdoor establishment by threat actors.
date: "2026-08-31T07:05:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - initial-access
  - network-security
  - rpc
  - exposure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: RPC is frequently targeted and exploited by threat actors as an initial access or backdoor vector.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It should almost never be directly exposed to the Internet, as it is frequently targeted and exploited by threat actors.
    confidence_band: high
rules:
  - title: Detect Inbound RPC Traffic from the Internet
    description: Detects TCP traffic on port 135 originating from outside the network and directed at internal IP address space.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - network_connection
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Network Security
    - SOC
  immediate_actions:
    - action: Deploy RPC exposure detection rule
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific logic to detect this threat.
  mitigation_plan:
    - priority: immediate
      action: Block all inbound traffic to TCP/135 from external IP ranges at the network edge
      owner: Network Operations
      addresses: RPC exposure
      evidence: Source states RPC should never be directly exposed to the internet.
---

Remote Procedure Call (RPC) is a fundamental protocol used for system administration and resource sharing within enterprise environments. When RPC services, specifically those listening on TCP port 135, are exposed directly to the public Internet, they provide a significant attack surface for threat actors. Attackers frequently scan for and target these exposed interfaces to gain initial access, execute arbitrary code, or establish persistent backdoors into internal network infrastructure. Because RPC is intended for local management, its presence on an internet-facing gateway is a primary indicator of misconfiguration or unauthorized access, necessitating immediate detection and remediation.

## Impact

Successful exploitation of exposed RPC services can lead to full system compromise, unauthorized lateral movement within the internal network, and potential data exfiltration. The severity of this threat is high as it bypasses traditional perimeter defenses, granting attackers a foothold within the internal environment. Organizations are at risk of ransomware deployment, credential theft, and persistent monitoring if such services remain internet-accessible.

## Recommendation

- Implement the provided detection logic to identify and alert on inbound TCP/135 traffic originating from non-RFC1918 (external) IP addresses.
- Isolate systems identified by this detection immediately from the Internet and perform a thorough security audit for signs of unauthorized access.
- Implement network segmentation and firewall rules to strictly deny any inbound traffic to TCP/135 from external sources.
- Audit all internal systems to ensure RPC is disabled on internet-facing network interfaces and rely on secure alternatives like VPNs for administrative access.
- Periodically scan the perimeter for exposed management ports to prevent accidental exposure of administrative services.
