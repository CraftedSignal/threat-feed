---
brief_id: brief-2026-10-29-anubis-santiam
event_id: brief-2026-10-29-anubis-santiam
revision: 1
activity_at: "2026-10-29T08:37:22Z"
title: 'Anubis Ransomware: Santiam Hospital & Clinics Data Breach'
slug: 2026-10-anubis-santiam
description: The Anubis ransomware-as-a-service group has claimed a new victim, Santiam Hospital & Clinics, following their established pattern of double-extortion attacks against the healthcare sector.
date: "2026-10-29T08:37:22Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Anubis
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
tags:
  - ransomware
  - healthcare
  - data-exfiltration
vendors:
  - Santiam Hospital & Clinics
products:
  - Santiam Hospital & Clinics
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: The group utilizes a double-extortion model involving data theft and encryption.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: The group utilizes a double-extortion model involving data theft and encryption, with an optional destructive 'wipe mode'.
    confidence_band: high
references:
  - https://www.ransomware.live/group/anubis
iocs:
  - type: hash_md5
    value: 054d432e231e8ee6e301675ef2bd598d
  - type: hash_md5
    value: 0a5f3fc92af7aa3e448ac7b84e495fc6
  - type: hash_md5
    value: 0f1b8aa83e5f9c40ad32561a95ed2c67
  - type: hash_md5
    value: 1b701df9e6b5252feef3d1d8dcfe12f5
  - type: hash_md5
    value: 241d01f08172a117268eb0f223348e47
  - type: hash_md5
    value: 24eae2bb569d97018d343fff50112dab
  - type: hash_md5
    value: 271998018494403a9b5d0d4b01eb0c44
  - type: hash_md5
    value: 284d536dab5865150873e927a29cb0ae
  - type: hash_md5
    value: 4f178cefbf3fc66baed13b3c4fa897d4
  - type: hash_md5
    value: 5334cbddd1128f87308c0725d2cb012e
  - type: hash_md5
    value: 71ce395e8bb531ec3623b94387de8392
  - type: hash_md5
    value: 832feae0378a9b36c4958812735b6d81
  - type: hash_md5
    value: 8a12e997e672b80319c5b852b237e5a9
  - type: hash_md5
    value: 994a0c3e3e1390d972b1bdd8e8f2a449
  - type: hash_md5
    value: 9ef845add689fc71cae33686139efbb0
  - type: hash_md5
    value: a1765503f1405b24b77a16071e6ea6f6
  - type: hash_md5
    value: a2d853247d939106231314bc5b233bda
  - type: hash_md5
    value: a4b88bf440613390cd32e045a59fd7b0
  - type: hash_md5
    value: c66022aa8b77a95c9b78a8743657f830
  - type: hash_md5
    value: d2410703e93be61a652b92efcf42789d
  - type: hash_md5
    value: d9a053e54be4003cc28b41fe30790349
  - type: hash_md5
    value: ed2510198b03435570d72ce274bc245c
  - type: hash_md5
    value: f1b5f6edfba8bf1312f65e7f2787c72f
  - type: hash_md5
    value: f71d8db7fda7659718330efcbd0776f0
  - type: hash_md5
    value: f8a242fa6a8df6eafded0a6987a5ac09
  - type: ip
    value: 195.133.67.35
  - type: ip
    value: 212.224.107.203
  - type: ip
    value: 38.134.148.20
  - type: ip
    value: 5.252.177.249
ioc_counts:
  hash_md5: 25
  ip: 4
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block Anubis C2 IP addresses on egress firewalls.
      owner: SOC
      due: 24h
      evidence: Anubis malicious infrastructure IPs found in source.
  hunt_leads:
    - lead: Search for established connections to listed Anubis IP addresses.
      data_needed:
        - Firewall or proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The group leverages infrastructure for data exfiltration.
  mitigation_plan:
    - priority: immediate
      action: Review data backup integrity and isolate off-site backups.
      owner: IT Operations
      addresses: Ransomware impact
      evidence: Anubis is a known RaaS operator using double-extortion.
---

The Anubis ransomware group has publicly claimed responsibility for a data breach at Santiam Hospital & Clinics. The group operates under a Ransomware-as-a-Service (RaaS) model and is known for double extortion, which involves exfiltrating sensitive medical data and encrypting organizational systems. The threat actor also provides affiliates with an optional destructive "wipe mode" to permanently delete data.

## Impact

The breach at Santiam Hospital & Clinics has resulted in the exposure of sensitive medical data. Anubis has listed the victim on its public-facing onion leak site, indicating intent to extort the organization.

## Recommendation

- Block the listed IP addresses at the perimeter firewall and web proxy to prevent communication with known Anubis infrastructure.
- Implement file integrity monitoring (FIM) and hunt for the presence of the provided MD5 hashes on endpoints to identify potential remnants of the Anubis ransomware payload.
- Prioritize monitoring of network traffic to and from healthcare infrastructure for unauthorized data staging or transfer, consistent with the double-extortion TTPs used by this group.
