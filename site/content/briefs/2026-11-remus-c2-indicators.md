---
brief_id: brief-2026-11-05-remus-c2-indicators
event_id: brief-2026-11-05-remus-c2-indicators
revision: 1
activity_at: "2026-11-05T13:39:45Z"
title: 'Remus Botnet: New command and control infrastructure'
slug: 2026-11-remus-c2-indicators
description: ThreatFox identified four new URL indicators associated with the Remus malware family used for command and control communication.
date: "2026-11-05T13:39:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - remus
  - botnet
  - c2
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.001
    subtechnique_name: Web Protocols
    evidence: ThreatFox identified four new C2 URLs associated with the Remus malware family.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.remus/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.remus
iocs:
  - type: url
    value: http://phetsre.shop:3452/files
  - type: url
    value: http://fgashub.shop:9932/files
  - type: url
    value: http://kkgemstone.com:5747
  - type: url
    value: http://flreaow.click:6527/teams
ioc_counts:
  url: 4
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block the four identified C2 URLs at the network perimeter
      owner: SOC
      due: 4h
      evidence: Indicators of compromise provided by ThreatFox
  hunt_leads:
    - lead: Identify endpoints initiating outbound network traffic to the provided domain and port list
      technique_id: T1071.001
      data_needed:
        - Network connection logs
        - Proxy logs
        - DNS query logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: New Remus C2 infrastructure identified
---

ThreatFox has reported four new URLs associated with the Remus malware family, observed on November 4, 2026. These indicators are identified as botnet command and control (C2) servers.

## Recommendation

- Block traffic to the listed URLs at the perimeter firewall and web proxy.
- Monitor network logs for outbound connections to the specified hostnames and ports.
- Investigate hosts that have successfully established connections to these C2 endpoints for potential compromise.
