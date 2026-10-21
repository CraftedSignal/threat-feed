---
brief_id: brief-2026-10-21-gs-pins-deserialization
event_id: brief-2026-10-21-gs-pins-deserialization
revision: 1
activity_at: "2026-10-21T11:19:40Z"
title: 'GS Plugins GS Pins for Pinterest: Deserialization of untrusted data (CVE-2026-110370)'
slug: 2026-10-gs-pins-deserialization
description: GS Plugins GS Pins for Pinterest contains a Deserialization of Untrusted Data vulnerability that allows Object Injection.
date: "2026-10-21T11:19:40Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:gs_plugins:gs_pins_for_pinterest:*:*:*:*:*:*:*:*
vendors:
  - GS Plugins
products:
  - GS Pins for Pinterest (n/a through 1.9.2)
cves:
  - id: CVE-2026-110370
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110370
---

CVE-2026-110370 identifies a Deserialization of Untrusted Data vulnerability in GS Plugins GS Pins for Pinterest, which allows for Object Injection. This issue affects versions from n/a through 1.9.2.

## Impact
The vulnerability has a CVSS v3.1 Base Score of 8.8.
