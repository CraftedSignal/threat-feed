---
brief_id: brief-2026-11-05-serorat-c2
event_id: brief-2026-11-05-serorat-c2
revision: 1
activity_at: "2026-11-05T13:33:43Z"
title: SeroRAT command and control infrastructure
slug: 2026-11-serorat-c2
description: ThreatFox identified a new command-and-control server (143.20.134.177:224) associated with the SeroRAT malware family.
date: "2026-11-05T13:33:43Z"
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
  - botnet
  - remote-access-trojan
  - command-and-control
  - malware
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.001
    subtechnique_name: Web Protocols
    evidence: ThreatFox listed 1 new Unknown RAT indicator of compromise (unknown_rat) first seen on 2026-11-04 UTC.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/unknown_rat/
iocs:
  - type: ip
    value: 143.20.134.177
ioc_counts:
  ip: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block 143.20.134.177 at the network perimeter.
      owner: SOC
      due: 4h
      evidence: Indicator reported as active SeroRAT C2 infrastructure.
  hunt_leads:
    - lead: Identify endpoints communicating with 143.20.134.177 on port 224.
      technique_id: T1071.001
      data_needed:
        - Firewall logs
        - Proxy logs
        - NetFlow data
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Reported botnet C2 activity.
---

ThreatFox has reported a new infrastructure indicator associated with the SeroRAT remote access trojan. The identified indicator is an IP address and port combination (143.20.134.177:224) acting as a botnet command-and-control (C2) node.

## Impact

Successful communication with this infrastructure may indicate a compromised host actively communicating with SeroRAT controllers, potentially facilitating unauthorized remote access, data exfiltration, or secondary payload delivery.

## Recommendation

- Block the IP address 143.20.134.177 on perimeter network devices and egress firewalls.
- Review historical firewall and proxy logs for any communication with the identified IP address.
- If matches are found, initiate incident response procedures to isolate the affected host and perform memory forensics to identify the SeroRAT persistence mechanism.
