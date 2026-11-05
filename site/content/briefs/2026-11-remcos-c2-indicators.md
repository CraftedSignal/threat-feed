---
brief_id: brief-2026-11-05-remcos-c2-indicators
event_id: brief-2026-11-05-remcos-c2-indicators
revision: 1
activity_at: "2026-11-05T13:39:39Z"
title: 'Remcos RAT: New command-and-control infrastructure'
slug: 2026-11-remcos-c2-indicators
description: ThreatFox identified 15 new command-and-control (C2) domains and IP addresses associated with active Remcos remote access trojan (RAT) infrastructure.
date: "2026-11-05T13:39:39Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
tags:
  - remcos
  - rat
  - c2
  - malware
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.001
    subtechnique_name: Web Protocols
    evidence: ThreatFox identified 15 new command-and-control (C2) indicators associated with the Remcos remote access trojan.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.remcos/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.remcos
iocs:
  - type: domain
    value: www.ndclassprojectnowduckdns2.com
  - type: domain
    value: www.ndclassprojectnowduckdns1.com
  - type: domain
    value: www.ndclassprojectnowduckdns.com
  - type: domain
    value: ndclassprojectnow.duckdns.org
  - type: ip
    value: 204.10.160.161
  - type: ip
    value: 38.240.61.250
  - type: ip
    value: 46.183.222.106
  - type: domain
    value: seniormanbk.duckdns.org
  - type: domain
    value: seniorman.duckdns.org
  - type: domain
    value: meme20.duckdns.org
  - type: ip
    value: 217.60.102.214
  - type: ip
    value: 193.187.91.224
  - type: domain
    value: newbiesemberbk.duckdns.org
  - type: domain
    value: newbiesember.duckdns.org
  - type: ip
    value: 217.60.102.78
ioc_counts:
  domain: 9
  ip: 6
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Ingest and block the listed IOCs in security appliances.
      owner: SOC
      due: 24h
      evidence: New Remcos infrastructure identified by abuse-ch.
  hunt_leads:
    - lead: Identify any internal network communication to the listed IP/domain IOCs.
      technique_id: T1071
      data_needed:
        - Proxy logs
        - DNS logs
        - Firewall logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: New Remcos C2 indicators listed by abuse-ch.
---

Abuse.ch ThreatFox has documented 15 new command-and-control (C2) indicators associated with the Remcos remote access trojan (RAT). These indicators, which include both domains and IP addresses, represent active infrastructure identified on 2026-11-04.

## Recommendation

* Block the domains and IP addresses listed in the IOC table at the DNS resolver and perimeter firewall.
* Search proxy and firewall logs for internal host communication with the identified C2 infrastructure.
* Audit endpoints for unauthorized persistence mechanisms often associated with Remcos, such as registry run keys or scheduled tasks.
