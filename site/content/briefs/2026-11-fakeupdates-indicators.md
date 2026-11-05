---
brief_id: brief-2026-11-05-fakeupdates-indicators
event_id: brief-2026-11-05-fakeupdates-indicators
revision: 1
activity_at: "2026-11-05T13:30:03Z"
title: FakeUpdates Indicators of Compromise
slug: 2026-11-fakeupdates-indicators
description: ThreatFox reported three new FAKEUPDATES (js.fakeupdates) indicators first seen on 2026-11-04.
date: "2026-11-05T13:30:03Z"
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
  - https://threatfox.abuse.ch/browse/malware/js.fakeupdates/
  - https://malpedia.caad.fkie.fraunhofer.de/details/js.fakeupdates
iocs:
  - type: domain
    value: img3.centovinipolska.com
  - type: url
    value: https://support.grovecityelectrician.com/ZtoCkR34YfgC+DijUe0usxWzZrNc6DKlUuozqEr4cLNc+Gf9DLZv8gG2erMb
  - type: domain
    value: support.grovecityelectrician.com
ioc_counts:
  domain: 2
  url: 1
---

ThreatFox listed three new FAKEUPDATES (js.fakeupdates) indicators of compromise first seen on 2026-11-04. The indicators consist of two domains classified as botnet_cc and one URL classified as payload_delivery.
