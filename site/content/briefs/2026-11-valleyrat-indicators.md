---
brief_id: brief-2026-11-05-valleyrat-indicators
event_id: brief-2026-11-05-valleyrat-indicators
revision: 1
activity_at: "2026-11-05T13:42:46Z"
title: ValleyRAT Remote Access Trojan Activity
slug: 2026-11-valleyrat-indicators
description: New infrastructure and payloads associated with the ValleyRAT remote access trojan were observed in the wild on 2026-11-04.
date: "2026-11-05T13:42:46Z"
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
  - valleyrat
  - malware
  - trojan
  - windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.001
    subtechnique_name: Web Protocols
    evidence: ThreatFox identified ValleyRAT C2 infrastructure facilitating remote control capabilities.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.valley_rat/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.valley_rat
iocs:
  - type: hash_md5
    value: 32f5f12dc1dc85423f2add8052adfeb6
  - type: hash_sha256
    value: 9a02a157acf5643e7ba6bcb422f093f7a681c184fcfa285c568e27803762dc49
ioc_counts:
  hash_md5: 1
  hash_sha256: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block infrastructure IOCs at perimeter firewall
      owner: SOC
      due: 24h
      evidence: Observed C2 ports 8888 and 6666 at 202.95.13.142
  hunt_leads:
    - lead: Identify endpoints communicating with the C2 IP range
      technique_id: T1071.001
      data_needed:
        - firewall_logs
        - proxy_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: C2 communication infrastructure identified by abuse-ch
---

Threat intelligence monitoring identified five new indicators of compromise related to the ValleyRAT remote access trojan on November 4, 2026. This activity includes three unique file hashes associated with the malware payload and two active command-and-control (C2) ports on the same remote IP address. ValleyRAT typically functions as a remote access tool providing attackers with persistent system control.

## Recommendation

* Block all outbound network traffic to the IP address 202.95.13.142 on ports 8888 and 6666 at the perimeter firewall.
* Implement file hash blocking or alerting for the provided MD5 and SHA-256 signatures on all managed Windows endpoints using an EDR or anti-malware solution.
* Hunt for internal hosts that have established successful TCP connections to the identified C2 ports within the last 30 days.
