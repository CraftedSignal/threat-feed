---
brief_id: brief-2026-11-05-ghost-rat
event_id: brief-2026-11-05-ghost-rat
revision: 1
activity_at: "2026-11-05T13:37:34Z"
title: Ghost RAT Indicator Update
slug: 2026-11-ghost-rat
description: ThreatFox reported one new indicator for the Ghost RAT malware family.
date: "2026-11-05T13:37:34Z"
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
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.ghost_rat
  - https://threatfox.abuse.ch/browse/malware/win.ghost_rat/
iocs:
  - type: hash_sha256
    value: d73f5eddae8d37b97c5844576ab4c78b49b222a174714f819be479913a6dfec5
ioc_counts:
  hash_sha256: 1
---

On 2026-11-04, ThreatFox identified one new indicator of compromise (IOC) associated with the Ghost RAT (win.ghost_rat) malware family.
