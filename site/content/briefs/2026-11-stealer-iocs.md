---
brief_id: brief-2026-11-05-stealer-iocs
event_id: brief-2026-11-05-stealer-iocs
revision: 1
activity_at: "2026-11-05T13:33:49Z"
title: New Unknown Stealer Indicators of Compromise
slug: 2026-11-stealer-iocs
description: ThreatFox identified 6 new indicators of compromise classified as 'unknown_stealer' on 2026-11-04.
date: "2026-11-05T13:33:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/unknown_stealer
  - https://threatfox.abuse.ch/browse/malware/unknown_stealer/
iocs:
  - type: domain
    value: shadowbirch.cc
  - type: domain
    value: res.shadowbirch.cc
  - type: domain
    value: bigriemp.com
ioc_counts:
  domain: 3
---

On 2026-11-04, ThreatFox reported 6 new indicators of compromise for 'unknown_stealer'. The indicators consist of 3 domains, 2 IP:port combinations, and 1 sha256 hash. The associated threat types include 5 botnet_cc and 1 payload.
