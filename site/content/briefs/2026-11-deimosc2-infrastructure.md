---
brief_id: brief-2026-11-05-deimosc2-infrastructure
event_id: brief-2026-11-05-deimosc2-infrastructure
revision: 1
activity_at: "2026-11-05T13:37:11Z"
title: DeimosC2 Command and Control Infrastructure
slug: 2026-11-deimosc2-infrastructure
description: ThreatFox has identified two new command-and-control infrastructure nodes associated with the DeimosC2 framework categorized as botnet controllers.
date: "2026-11-05T13:37:11Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against ThreatFox source.
tags:
  - deimosc2
  - c2
  - botnet
  - network-security
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The indicators are categorized as botnet controllers, specifically linked to the Deimos and drb-ra tags.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.deimos_c2/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.deimos_c2
iocs:
  - type: ip
    value: 46.4.120.252
  - type: ip
    value: 46.4.120.244
ioc_counts:
  ip: 2
action_plan:
  priority: elevated
  owners:
    - SOC
  immediate_actions:
    - action: Block C2 IPs at firewall and proxy
      owner: SOC
      due: 4h
      evidence: IOCs reported by Abuse.ch for active DeimosC2 infrastructure.
  hunt_leads:
    - lead: Network connections to known DeimosC2 IP addresses
      technique_id: T1071
      data_needed:
        - Firewall/Proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: New DeimosC2 indicators identified on 2026-11-04.
---

Abuse.ch has reported two new IP addresses acting as command-and-control (C2) nodes for the DeimosC2 framework. The infrastructure is tagged with 'Deimos' and 'drb-ra' and was first observed on 2026-11-04.

## Recommendation

- Block traffic to the listed IP addresses at the perimeter firewall and egress proxy.
- Initiate hunting for network connections to these IPs using existing flow logs or firewall telemetry.
