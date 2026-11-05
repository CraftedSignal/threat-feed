---
brief_id: brief-2026-11-05-netwire-indicators
event_id: brief-2026-11-05-netwire-indicators
revision: 1
activity_at: "2026-11-05T13:38:54Z"
title: 'NetWire RC: New Indicator Update'
slug: 2026-11-netwire-indicators
description: ThreatFox reported three new payload indicators of compromise associated with NetWire RC on 2026-11-04.
date: "2026-11-05T13:38:54Z"
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
  - https://threatfox.abuse.ch/browse/malware/win.netwire/
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.netwire
iocs:
  - type: hash_md5
    value: e89632a73f0657995d5394173b64a513
  - type: hash_sha1
    value: 81beedfdecc403cbf3bae371c7efbee362100d76
  - type: hash_sha256
    value: 61e6fe15b423177661294e31bf32f9112bfb531a71a79327eb8dbc732278e8c1
ioc_counts:
  hash_md5: 1
  hash_sha1: 1
  hash_sha256: 1
---

On November 4, 2026, ThreatFox identified three new indicators of compromise for the NetWire RC malware (win.netwire). The indicators consist of one MD5 hash, one SHA1 hash, and one SHA256 hash, all categorized as payloads with a confidence level of 95%.
