---
title: LegionRelay C2 Infrastructure Targeting Ukrainian Entities
slug: 2026-10-legionrelay-c2
description: Threat actors are employing the LegionRelay command-and-control framework to facilitate malicious operations against organizations within Ukraine, necessitating network-based detection for C2 traffic.
date: "2026-10-15T19:27:46Z"
type: rumour
types:
  - rumour
severities:
  - rumour
tags:
  - legionrelay
  - c2
  - ukraine
  - network-security
  - threat-intelligence
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Detection should focus on identifying network communication patterns associated with this C2 framework.
    confidence_band: high
action_plan:
  priority: enrich_before_decision
  owners:
    - CTI
    - SOC
  enrichment_needed:
    - item: LegionRelay C2 infrastructure indicators
      owner: CTI
      reason: No specific IP addresses or domain names were provided in the source report; enrichment from threat intelligence feeds is required to build actionable blocks.
      evidence: None extracted from the source.
  hunt_leads:
    - lead: Anomalous outbound network connections to unfamiliar or low-reputation infrastructure
      technique_id: T1071.001
      data_needed:
        - Network logs (Firewall, Proxy, DNS)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: LegionRelay infrastructure acts as an intermediary, requiring network visibility for detection.
---

Security research by Team Cymru has identified a campaign utilizing the LegionRelay command-and-control (C2) infrastructure to target entities in Ukraine. LegionRelay acts as an intermediary layer in the attacker's infrastructure, designed to obscure the backend C2 servers while facilitating communication between compromised endpoints and the threat actor's primary command servers. This infrastructure is specifically observed in operations aimed at Ukrainian targets, highlighting a persistent focus on the region. For defenders, identifying the network patterns associated with these relay nodes is critical for disrupting the adversary's communication flow and preventing the exfiltration of data or the deployment of secondary payloads. Organizations with a footprint in the region or those managing infrastructure relevant to Ukrainian entities should prioritize visibility into network telemetry to identify potential connections to these relay nodes.

## Impact

The observed activity poses a significant risk to the integrity and confidentiality of target networks within Ukraine. Successful establishment of a connection to LegionRelay infrastructure allows attackers to maintain persistent access, issue remote commands, and exfiltrate sensitive data. If left undetected, this C2 infrastructure provides attackers with a reliable conduit for long-term espionage and operational disruption against critical infrastructure, government agencies, and private sectors operating within the targeted geography.

## Recommendation

Prioritize the implementation of network monitoring capabilities to identify and block traffic patterns associated with known LegionRelay relays, utilizing threat intelligence feeds that incorporate current C2 infrastructure discovery. Engage in proactive hunting within network logs (DNS, proxy, and firewall) for anomalous outbound connections to external infrastructure that exhibit characteristics of C2 heartbeats or non-standard protocol tunneling. Since the source documentation currently lacks specific indicators, defenders should review internal network logs for unusual volumes of traffic to non-reputable external IP addresses or domains identified through threat intel sharing platforms or community-sourced detection initiatives.
