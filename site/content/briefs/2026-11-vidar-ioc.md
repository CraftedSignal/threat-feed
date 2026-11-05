---
brief_id: brief-2026-11-05-vidar-ioc
event_id: brief-2026-11-05-vidar-ioc
revision: 1
activity_at: "2026-11-05T13:42:52Z"
title: 'Vidar Stealer: New command-and-control infrastructure'
slug: 2026-11-vidar-ioc
description: ThreatFox identified 162 new indicators associated with the Vidar information stealer, primarily consisting of active command-and-control domains and IP addresses.
date: "2026-11-05T13:42:52Z"
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
  - vidar
  - malware
  - stealer
  - c2
  - botnet
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: 156 indicators are categorized as botnet_cc
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.vidar/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar
iocs:
  - type: domain
    value: cuit8.org
  - type: domain
    value: alloha4d.org
  - type: domain
    value: allbaslot.org
  - type: hash_sha256
    value: 423f9649baabc8864818e9fd3234df4841eced82f8663bac490ed3cde93c306c
  - type: hash_sha256
    value: 0f08e05e915c9628fb031623dbc63e1b40fcb7066659e7c969c3d08b9c43f734
  - type: ip
    value: 2.29.152.8
ioc_counts:
  domain: 3
  hash_sha256: 2
  ip: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block listed domains and IP addresses at perimeter firewall and DNS sinkhole.
      owner: SOC
      due: 4h
      evidence: New Vidar infrastructure identified by ThreatFox.
  hunt_leads:
    - lead: Identify endpoints communicating with the identified C2 IPs and domains
      technique_id: T1071
      data_needed:
        - Proxy logs
        - DNS query logs
        - Netflow
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: New list of 162 Vidar indicators of compromise provided by abuse-ch.
---

On November 4, 2026, ThreatFox reported 162 new indicators of compromise (IOCs) associated with the Vidar information stealer. The updated intelligence includes 156 indicators categorized as botnet command-and-control (C2) infrastructure and 6 malicious payload samples. The infrastructure consists of 98 URLs, 51 domains, and 7 IP:port combinations.

## Impact
Vidar is an information-stealing malware designed to exfiltrate sensitive data, including browser credentials, cryptocurrency wallets, and system configuration information, to attacker-controlled infrastructure.

## Recommendation
- Block the listed C2 domains and IP addresses at the organizational DNS resolver and firewall.
- Implement file integrity monitoring or EDR blocks for the identified SHA-256 file hashes to prevent payload execution.
- Prioritize threat hunting for network connections to the provided IP addresses and domain infrastructure.
