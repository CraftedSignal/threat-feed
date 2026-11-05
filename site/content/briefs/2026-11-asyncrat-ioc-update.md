---
brief_id: brief-2026-11-05-asyncrat-ioc-update
event_id: brief-2026-11-05-asyncrat-ioc-update
revision: 1
activity_at: "2026-11-05T13:34:16Z"
title: ThreatFox AsyncRAT Indicator Update
slug: 2026-11-asyncrat-ioc-update
description: ThreatFox reported 14 new indicators of compromise for AsyncRAT (win.asyncrat) first seen on 2026-11-04.
date: "2026-11-05T13:34:16Z"
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
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat
  - https://threatfox.abuse.ch/browse/malware/win.asyncrat/
iocs:
  - type: domain
    value: prakashjadhav747.duckdns.org
  - type: domain
    value: prakahjadhav74.duckdns.org
ioc_counts:
  domain: 2
---

ThreatFox has identified 14 new indicators of compromise related to AsyncRAT, categorized as follows:
- Botnet Command and Control (8)
- Payloads (6)

Indicator types include IP:port combinations, domains, MD5 hashes, SHA1 hashes, and SHA256 hashes.
