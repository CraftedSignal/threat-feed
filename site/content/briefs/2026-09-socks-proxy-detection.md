---
title: Detection of Anomalous SOCKS Proxy Traffic via FortiGate Integration
slug: 2026-09-socks-proxy-detection
description: This detection leverages cross-platform correlation between FortiGate network application logs and endpoint telemetry to identify processes acting as SOCKS proxies for potential command and control obfuscation.
date: "2026-09-18T19:05:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - proxy
  - network-security
  - cross-platform
vendors:
  - Fortinet
products:
  - FortiGate
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1090/
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_socks_fortigate_endpoint.toml
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy correlation rule for FortiGate SOCKS logs and endpoint network events
      owner: Detection Engineering
      due: 72h
  hunt_leads:
    - lead: Processes exhibiting high volumes of outbound network connections correlated with SOCKS protocol signatures
      technique_id: T1090
      data_needed:
        - Endpoint network events
        - FortiGate application logs
      priority: medium
      confidence: medium
      disposition: hunt_now
  mitigation_plan:
    - priority: short_term
      action: Restrict outbound SOCKS traffic at the network perimeter via ACLs
      owner: Network Security
      addresses: T1090
---

Adversaries frequently employ connection proxies, such as SOCKS4 and SOCKS5, to direct network traffic through intermediaries. This technique obfuscates the origin of command and control (C2) traffic, allowing attackers to bypass perimeter security controls and avoid direct connections to their infrastructure.

The current detection logic, developed by Elastic, facilitates the identification of these proxies by correlating FortiGate application control SOCKS events with host-level network events. By matching source IP, source port, and destination IP parameters between network perimeter logs and endpoint-level connection attempts or disconnections within a one-minute window, defenders can isolate the specific process responsible for the proxy activity. This approach is essential for detecting covert C2 communication channels that would otherwise blend in with standard network traffic.

## Impact

Successful proxy-based C2 communication allows attackers to maintain persistence, conduct lateral movement, and exfiltrate data while masking their true infrastructure. This activity frequently precedes more damaging operations, including ransomware deployment or large-scale data theft. If left undetected, this proxy behavior provides a persistent channel for unauthorized network traffic that can be difficult to remediate due to the obfuscated nature of the connection.

## Recommendation

Detection engineering teams should implement the following steps:
- Deploy the provided correlation logic to the SIEM, ensuring both Elastic Defend network events and FortiGate logs are ingested.
- Tune the detection for environment-specific noise, specifically excluding known-good browser proxy extensions, legitimate deployment tools, and authorized third-party administrative utilities.
- Establish a process for triaging identified processes by reviewing parent-child execution chains and local port forwarding patterns.
- Implement network-level egress filtering to restrict SOCKS traffic to pre-approved destinations only.
