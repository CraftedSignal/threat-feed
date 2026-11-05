---
brief_id: brief-2026-11-05-jackskid-c2
event_id: brief-2026-11-05-jackskid-c2
revision: 1
activity_at: "2026-11-05T13:29:13Z"
title: Jackskid botnet command-and-control infrastructure
slug: 2026-11-jackskid-c2
description: ThreatFox has identified 8 new C2 server indicators associated with the Jackskid botnet, a Mirai-based variant utilized for DDoS attacks.
date: "2026-11-05T13:29:13Z"
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
  - ddos
  - mirai
  - jackskid
  - network-security
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: The indicators utilize port 443 for command-and-control communication, suggesting an attempt to blend into standard HTTPS traffic.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/elf.jackskid/
  - https://malpedia.caad.fkie.fraunhofer.de/details/elf.jackskid
  - https://github.com/deepfield/public-research/tree/main/jackskid
iocs:
  - type: ip
    value: 96.62.250.142
  - type: ip
    value: 172.233.14.200
  - type: ip
    value: 172.233.47.155
  - type: ip
    value: 172.233.1.13
  - type: ip
    value: 109.110.170.72
  - type: ip
    value: 168.144.176.164
  - type: ip
    value: 188.166.233.203
  - type: ip
    value: 170.64.153.147
ioc_counts:
  ip: 8
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block the 8 listed C2 IP addresses on all internet-facing firewalls and proxy devices.
      owner: SOC
      due: 24h
      evidence: Source lists these as confirmed C2 indicators for the Jackskid botnet.
  hunt_leads:
    - lead: Identify outbound connections from internal Linux infrastructure to the listed IP addresses on port 443.
      technique_id: T1071.001
      data_needed:
        - NetFlow logs
        - Firewall traffic logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Jackskid uses port 443 for C2 communication.
---

ThreatFox reported 8 new indicators of compromise for the Jackskid (elf.jackskid) botnet. The indicators consist of IP addresses communicating over port 443, suggesting an attempt to masquerade command-and-control traffic as standard HTTPS. Jackskid is a known variant of the Mirai malware family used primarily for distributed denial-of-service (DDoS) operations.

## Recommendation

- Block the identified C2 IP addresses at the perimeter firewall and egress proxy.
- Implement network monitoring to detect outbound connections from internal assets to these specific IP addresses on port 443.
- Review historical logs for any existing connections to the provided IOCs to identify potentially compromised internal endpoints.
