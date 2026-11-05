---
brief_id: brief-2026-11-05-netsupportmanager-rat
event_id: brief-2026-11-05-netsupportmanager-rat
revision: 1
activity_at: "2026-11-05T13:38:48Z"
title: NetSupportManager RAT Infrastructure Indicators
slug: 2026-11-netsupportmanager-rat
description: Abuse.ch has identified 18 new command and control indicators, including 17 IP addresses and one domain, associated with the NetSupportManager remote access trojan.
date: "2026-11-05T13:38:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
tags:
  - botnet
  - rat
  - network
  - command-and-control
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.001
    subtechnique_name: Web Protocols
    evidence: The indicators are categorized as botnet_cc, identifying them as infrastructure used for RAT communication.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.netsupportmanager_rat/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.netsupportmanager_rat
iocs:
  - type: ip
    value: 95.85.246.222
  - type: ip
    value: 94.181.203.45
  - type: ip
    value: 89.105.217.188
  - type: ip
    value: 85.239.144.93
  - type: ip
    value: 77.105.141.234
  - type: ip
    value: 62.164.177.248
  - type: ip
    value: 5.253.59.121
  - type: ip
    value: 5.252.155.120
  - type: ip
    value: 193.143.1.21
  - type: ip
    value: 176.65.144.140
  - type: ip
    value: 176.65.144.133
  - type: ip
    value: 162.33.179.223
  - type: ip
    value: 162.19.130.138
  - type: ip
    value: 151.243.18.118
  - type: ip
    value: 144.76.188.73
  - type: ip
    value: 108.61.198.38
  - type: ip
    value: 93.232.110.114
  - type: domain
    value: agreement-rc.com
ioc_counts:
  domain: 1
  ip: 17
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block listed IP addresses and domain on perimeter firewalls and DNS resolvers
      owner: SOC
      due: 4h
      evidence: New infrastructure identified by ThreatFox
  hunt_leads:
    - lead: Identify endpoints communicating with the listed C2 infrastructure
      technique_id: T1071.001
      data_needed:
        - Network proxy logs
        - DNS request logs
        - Firewall traffic logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Confirmed C2 indicators active as of 2026-11-04
---

ThreatFox has published 18 newly observed command and control (C2) indicators associated with the NetSupportManager RAT, a remote access tool frequently abused by threat actors for unauthorized system access. These indicators were confirmed active as of November 4, 2026.

## Recommendation
- Block the domain 'agreement-rc.com' at the enterprise DNS resolver.
- Implement egress traffic blocking for the identified C2 IP addresses at the perimeter firewall.
- Review network logs for historical connections to these indicators to identify potential prior compromise.
