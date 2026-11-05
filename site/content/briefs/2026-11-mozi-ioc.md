---
brief_id: brief-2026-11-05-mozi-ioc
event_id: brief-2026-11-05-mozi-ioc
revision: 1
activity_at: "2026-11-05T13:29:35Z"
title: New Mozi Indicators of Compromise
slug: 2026-11-mozi-ioc
description: ThreatFox listed 8 new Mozi indicators of compromise (elf.mozi) first seen on 2026-11-04 UTC.
date: "2026-11-05T13:29:35Z"
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
  - https://malpedia.caad.fkie.fraunhofer.de/details/elf.mozi
  - https://threatfox.abuse.ch/browse/malware/elf.mozi/
iocs:
  - type: url
    value: http://103.213.112.98:33872/Mozi.7
  - type: url
    value: http://139.135.40.157:41777/Mozi.m
  - type: url
    value: http://103.82.121.8:48818/Mozi.m
  - type: url
    value: http://123.10.155.244:48308/Mozi.a
  - type: url
    value: http://103.244.172.242:50277/Mozi.m
  - type: url
    value: http://202.47.55.104:33505/Mozi.a
  - type: url
    value: http://153.117.50.75:44089/Mozi.m
  - type: url
    value: http://153.117.37.137:39548/Mozi.m
ioc_counts:
  url: 8
---

ThreatFox has identified 8 new URLs associated with the Mozi (elf.mozi) malware. All indicators are categorized as payload_delivery.
