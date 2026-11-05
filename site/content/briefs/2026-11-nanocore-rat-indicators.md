---
brief_id: brief-2026-11-05-nanocore-rat-indicators
event_id: brief-2026-11-05-nanocore-rat-indicators
revision: 1
activity_at: "2026-11-05T13:38:42Z"
title: 'Nanocore RAT: New Infrastructure and Payload Indicators'
slug: 2026-11-nanocore-rat-indicators
description: ThreatFox identified new Nanocore RAT payloads and C2 infrastructure, indicating active maintenance of distribution and communication channels.
date: "2026-11-05T13:38:42Z"
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
tags:
  - nanocore
  - rat
  - malware
  - c2
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: Nanocore RAT botnet_cc identified via domain and IP
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.nanocore/
iocs:
  - type: hash_md5
    value: 517d2813b2a61f0aebe628dd8ffbf2c9
  - type: hash_sha256
    value: d0c49323ffadf825f022fd40f36772c7665d0f548a341d43347318e183fd42d6
  - type: hash_md5
    value: d1794ae26eca56b6f101039774d08b95
  - type: hash_sha256
    value: 352cfb22ba4830b5c184041bf4457a21580e44bdfa66f615e003799c3a76fc97
  - type: domain
    value: adobeupdate.ddns.net
  - type: ip
    value: 31.59.137.16
ioc_counts:
  domain: 1
  hash_md5: 2
  hash_sha256: 2
  ip: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block identified C2 domain and IP address at the network boundary
      owner: SOC
      due: 2h
      evidence: IOC list from ThreatFox
    - action: Check endpoint logs for the identified SHA-256 and MD5 file hashes
      owner: SOC
      due: 4h
      evidence: Payload list from ThreatFox
  hunt_leads:
    - lead: Identify endpoints initiating network connections to 31.59.137.16:3998 or resolving adobeupdate.ddns.net
      technique_id: T1071.001
      data_needed:
        - Proxy logs
        - DNS query logs
        - Firewall traffic logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: IOCs provided by ThreatFox
---

ThreatFox has reported eight new indicators of compromise related to the Nanocore remote access trojan (RAT), consisting of malicious payloads and command-and-control (C2) infrastructure. These indicators reflect ongoing activity involving Nanocore, a known commodity RAT that provides attackers with extensive remote control capabilities over compromised Windows systems.

## Impact

The identified C2 infrastructure (a dynamic DNS domain and a hardcoded IP address) allows for the remote management of infected hosts. The associated file hashes represent active payloads used in current distribution efforts.

## Recommendation

- Block the identified C2 domain and IP address at your perimeter firewall and DNS resolvers.
- Implement file integrity monitoring to detect the presence of the identified malicious hashes on endpoints.
- Perform a threat hunt across EDR telemetry for connections to the identified C2 infrastructure.
