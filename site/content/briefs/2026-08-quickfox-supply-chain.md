---
title: QuickFox Supply Chain Attack and FDMTP Implant Deployment
slug: 2026-08-quickfox-supply-chain
description: Threat actors compromised QuickFox software supply chain to distribute trojanized Windows installers, resulting in the installation of a custom FDMTP implant for persistent access.
date: "2026-08-04T13:43:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain-attack
  - implant
  - windows
  - fortiguard
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Supply Chain Compromise
    evidence: The FortiGuard Labs Incident Response team analyzes a QuickFox supply chain attack that used trojanized Windows installers.
    confidence_band: high
references:
  - https://feeds.fortinet.com/~/966214247/0/fortinet/blog/threat-research~QuickFox-Supply-Chain-Attack-Used-to-Deploy-FDMTP-Implant
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Integrity audit of installed QuickFox binaries and verification against known good hashes
      owner: IT Operations
      due: 48h
      evidence: Source identifies trojanized installers as the primary vector.
  hunt_leads:
    - lead: Investigation of unauthorized persistence mechanisms (Registry keys/Scheduled Tasks) on hosts running QuickFox
      technique_id: T1547
      data_needed:
        - Process creation events
        - Registry modifications
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Threat involves deployment of FDMTP implant for persistence.
---

The FortiGuard Labs Incident Response team has identified a sophisticated supply chain attack targeting users of the QuickFox application. Attackers successfully trojanized legitimate Windows installers, allowing them to gain initial access to victim environments through a trusted delivery mechanism. Upon execution of the compromised installer, the attack proceeds to deploy a custom, evolving malware implant identified as FDMTP. This implant is designed for persistent access and modular functionality, enabling the operators to conduct targeted operations within compromised networks. The selective nature of the targeting suggests a focused campaign rather than indiscriminate mass distribution, which increases the risk to enterprise environments that rely on this software for network optimization. Defenders should prioritize auditing the integrity of software deployment pipelines and monitoring for unauthorized persistence mechanisms associated with this implant.

## Impact

The impact of this campaign involves potential unauthorized access to target systems, potential exfiltration of sensitive information, and long-term persistence in affected environments. The specific targeting indicates that selected organizations are at higher risk of compromise. Organizations utilizing QuickFox should conduct immediate forensic reviews of endpoints where the software is deployed to detect unauthorized modification or presence of the FDMTP implant.

## Recommendation

* Perform a baseline integrity audit of the QuickFox installation files across all endpoints to ensure they match legitimate vendor signatures.
* Monitor for unexpected processes spawned by software installers or updater binaries.
* Review endpoint telemetry for suspicious persistence mechanisms, specifically looking for anomalous registry modifications or scheduled tasks created shortly after software installation events.
* Isolate systems where QuickFox was updated or reinstalled during the identified campaign window for forensic analysis.
