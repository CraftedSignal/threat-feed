---
brief_id: brief-2026-11-05-njrat-indicators
event_id: brief-2026-11-05-njrat-indicators
revision: 1
activity_at: "2026-11-05T13:39:05Z"
title: NjRAT Command and Control Infrastructure and Payload Updates
slug: 2026-11-njrat-indicators
description: New NjRAT (Bladabindi) remote access trojan payloads and C2 infrastructure were identified on 2026-11-04, enabling remote system takeover.
date: "2026-11-05T13:39:05Z"
type: advisory
types:
  - advisory
severities:
  - high
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
  - njrat
  - malware
  - rat
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: NjRAT botnet_cc identified at 104.248.130.195:7488
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: NjRAT typically functions as a remote access trojan capable of executing arbitrary commands.
    confidence_band: med
references:
  - https://threatfox.abuse.ch/browse/malware/win.njrat/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat
  - https://bazaar.abuse.ch/sample/346da41883ade4968090ae72dc1c1f011dde9b248b21d5e2573851ef810245a5/
iocs:
  - type: hash_md5
    value: 43ba5a3f20774f2ac402d8b310825f84
  - type: hash_md5
    value: 87e0a229df9796c373e0a48031df949b
  - type: hash_sha256
    value: df565eec185189cd6281e541953975959b81524626f38272a85b6eef71c4ec16
  - type: hash_sha256
    value: 764f0fae11de72f3c80fd07118ef290a2e432aa3d90e57443610a83317d738fe
  - type: ip
    value: 104.248.130.195
ioc_counts:
  hash_md5: 2
  hash_sha256: 2
  ip: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block C2 IP 104.248.130.195 at perimeter
      owner: SOC
      due: 4h
      evidence: Observed active C2 infrastructure
    - action: Add payload hashes to EDR blocklist
      owner: SOC
      due: 4h
      evidence: NjRAT confirmed malware payloads
  hunt_leads:
    - lead: Identify outbound network traffic to 104.248.130.195 on port 7488
      technique_id: T1071
      data_needed:
        - Firewall logs
        - Netflow data
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Active C2 IP identified in threat report
---

ThreatFox reported seven new indicators of compromise related to NjRAT, a Remote Access Trojan (RAT). These indicators include malicious payloads and active command-and-control (C2) infrastructure identified on November 4, 2026. NjRAT, also known as Bladabindi, provides attackers with full remote system control.

## Impact
Successful execution of the identified payloads results in unauthorized remote access, file system manipulation, and potential data exfiltration from compromised Windows hosts.

## Recommendation
- Block the C2 IP address 104.248.130.195 on perimeter firewalls and web proxies.
- Scan endpoint file systems for the identified MD5 and SHA-256 payload hashes.
- Implement EDR blocklisting for the identified hash values to prevent execution.
