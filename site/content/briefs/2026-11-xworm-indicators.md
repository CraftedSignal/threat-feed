---
brief_id: brief-2026-11-05-xworm-indicators
event_id: brief-2026-11-05-xworm-indicators
revision: 1
activity_at: "2026-11-05T13:43:18Z"
title: XWorm Malware Indicators of Compromise
slug: 2026-11-xworm-indicators
description: Abuse.ch has identified 15 new indicators of compromise for the XWorm remote access trojan, including multiple command-and-control IP addresses and malicious file hashes.
date: "2026-11-05T13:43:18Z"
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
  - xworm
  - rat
  - malware
  - botnet
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: ThreatFox identified botnet command-and-control infrastructure for XWorm malware.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/win.xworm/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.xworm
iocs:
  - type: ip
    value: 36.255.97.22
  - type: hash_md5
    value: 28474a8e74704e05c1220aeff44cee9b
  - type: hash_sha256
    value: 0446aa974dff931e43c2284a74099cd256f3bbd8b7098be489267a6b9d65b4f7
  - type: ip
    value: 217.60.103.38
  - type: ip
    value: 36.255.97.226
  - type: ip
    value: 45.141.21.235
  - type: ip
    value: 5.175.166.90
  - type: domain
    value: mrv001.ddns.net
ioc_counts:
  domain: 1
  hash_md5: 1
  hash_sha256: 1
  ip: 5
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block C2 domain and IP addresses listed in the IOC section.
      owner: SOC
      due: 4h
      evidence: New XWorm infrastructure reported on 2026-11-04.
  hunt_leads:
    - lead: Hunt for outbound network connections to ports 7007, 7575, 4445, and 6604.
      technique_id: T1071
      data_needed:
        - Firewall or NetFlow logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Multiple C2 indicators were associated with these specific ports in the source report.
---

On November 4, 2026, ThreatFox reported 15 new indicators of compromise (IOCs) associated with the XWorm malware, a Windows-based remote access trojan (RAT). The identified infrastructure includes active command-and-control (C2) servers and hashes for malicious payloads currently circulating in the wild.

## Impact

XWorm is a multi-purpose RAT capable of data exfiltration, system manipulation, and serving as a secondary payload delivery mechanism. The newly identified C2 infrastructure represents potential active command-and-control channels for compromised endpoints.

## Recommendation

- Implement blocking for the provided C2 IP addresses and domain at the network perimeter.
- Scan endpoint and email gateway environments for the identified malicious file hashes.
- Monitor for suspicious network connections originating from Windows hosts to the identified non-standard ports (e.g., 7007, 7575, 4445).
