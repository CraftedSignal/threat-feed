---
brief_id: brief-2026-11-05-vshell-indicators
event_id: brief-2026-11-05-vshell-indicators
revision: 1
activity_at: "2026-11-05T13:42:57Z"
title: VShell Malware Command and Control Infrastructure
slug: 2026-11-vshell-indicators
description: ThreatFox identified 61 new indicators of compromise related to the VShell malware family, including multiple malicious payload hashes and active command-and-control IP addresses.
date: "2026-11-05T13:42:57Z"
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
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - malware
  - botnet
  - c2
  - threatfox
  - vshell
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: VShell infrastructure identified as botnet_cc.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.vshell/
iocs:
  - type: ip
    value: 43.161.243.73
  - type: ip
    value: 165.154.45.137
  - type: hash_sha256
    value: 7a7b1c234c94c4a20540c2be5b94cb193dc16bdb263b6bb11762f25db27bdc30
ioc_counts:
  hash_sha256: 1
  ip: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block identified C2 IP addresses at the enterprise edge firewall
      owner: SOC
      due: 24h
      evidence: ThreatFox list of active botnet C2 servers
  hunt_leads:
    - lead: Identify endpoints communicating with the listed C2 IP addresses
      technique_id: T1071
      data_needed:
        - Network proxy logs
        - Firewall traffic logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 16 listed IP addresses identified as active botnet C2
---

On November 4, 2026, ThreatFox published 61 new indicators of compromise associated with the VShell malware family (win.vshell). The identified infrastructure includes 16 IP addresses serving as botnet command-and-control (C2) servers and 45 associated payloads identified by various file hashes. These indicators were reported by multiple contributors and represent active malware infrastructure.

## Recommendation

- Ingest the provided IP addresses into your perimeter blocklists and monitor for outbound connections from internal assets to these addresses.
- Calculate file hashes for suspicious binaries observed in the environment and compare them against the provided IOC list to detect VShell payload distribution.
- Conduct retrospective threat hunting in proxy and DNS logs for historical communication with the listed C2 infrastructure.
