---
brief_id: brief-2026-11-05-wardenstealer-indicators
event_id: brief-2026-11-05-wardenstealer-indicators
revision: 1
activity_at: "2026-11-05T13:43:09Z"
title: WARDENStealer Campaign Infrastructure Update
slug: 2026-11-wardenstealer-indicators
description: New command-and-control infrastructure and payload hashes for WARDENStealer information-stealing malware were identified on November 4, 2026.
date: "2026-11-05T13:43:09Z"
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
  - wardenstealer
  - information-stealer
  - botnet
  - malware
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: The malware utilizes a network of command-and-control (C2) servers to exfiltrate data.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204.002
    technique_name: Malicious File
    evidence: The malware is delivered as an executable payload.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.warden_stealer/
iocs:
  - type: url
    value: https://stapbystep.rest/
  - type: url
    value: https://pi-suxa56.mom/
  - type: url
    value: https://hilgapotaki.com/
  - type: url
    value: https://yoobyjus.com/
  - type: url
    value: https://dataportlymy.guru/
  - type: url
    value: https://veltrika.qpon/
  - type: url
    value: https://popochka.cc/
  - type: url
    value: https://vexaltrion.rest/
  - type: url
    value: https://pidoras-12.rest/
  - type: url
    value: https://scouybydyh.com/
  - type: url
    value: https://magomyyry.com/
  - type: url
    value: https://pluginstopsyka.com/
  - type: url
    value: https://polariscolap.rest/
  - type: url
    value: https://vuiniqu.rest/
  - type: url
    value: https://delopaten.rest/
  - type: url
    value: https://zyntravio.rest/
  - type: url
    value: https://eptabiboko.com/
  - type: url
    value: https://randfom2323.com/
  - type: hash_sha256
    value: 173a09636a91e303c6466a26ab0d84e156886d28d648f37b6ef9f1656af6471e
  - type: hash_sha256
    value: 7b0a6911dae45311ebed9f4397af4b129b2c893f87e8166c85d7a85db7298af4
  - type: url
    value: https://rabbids-youtube.cc/
  - type: url
    value: https://contupasserworld.guru/
  - type: url
    value: https://beawlopman.guru/
ioc_counts:
  hash_sha256: 2
  url: 21
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block all listed C2 URLs on network egress points.
      owner: SOC
      due: 2h
      evidence: ThreatFox reports these URLs as active WARDENStealer botnet C2 nodes.
  hunt_leads:
    - lead: Identify endpoints attempting to reach the listed C2 domains.
      technique_id: T1071.001
      data_needed:
        - DNS request logs
        - Proxy access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Active command-and-control communication is a core function of the malware.
---

ThreatFox identified 23 new indicators of compromise related to the WARDENStealer information stealer. The indicators include 21 command-and-control (C2) URLs and two malicious binary payloads. This activity was reported by community contributors and reflects current infrastructure used by the operator.

## Impact
WARDENStealer is designed to exfiltrate sensitive data from infected systems. Observed impact is limited to the identification of active C2 domains and binary hashes used in ongoing campaigns.

## Recommendation
- Block the identified C2 URLs at the organizational web proxy or DNS resolver.
- Implement file integrity monitoring and endpoint detection to alert on the execution of the provided SHA-256 hashes.
- Scan historical telemetry for outbound connections to the listed C2 domains.
