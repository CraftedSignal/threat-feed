---
brief_id: brief-2026-10-24-events-manager-xss
event_id: brief-2026-10-24-events-manager-xss
revision: 1
activity_at: "2026-10-24T10:12:27Z"
title: 'Pixelite Events Manager: Reflected Cross-site Scripting (CVE-2026-114694)'
slug: 2026-10-events-manager-xss
description: The Pixelite Events Manager plugin contains an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability, allowing Reflected XSS.
date: "2026-10-24T10:12:27Z"
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
  - cpe:2.3:a:pixelite:events_manager:*:*:*:*:*:*:*:*
vendors:
  - Pixelite
products:
  - Events Manager (n/a through 7.4.8)
cves:
  - id: CVE-2026-114694
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114694
---

Pixelite Events Manager (through version 7.4.8) is affected by a Reflected Cross-site Scripting (XSS) vulnerability due to improper neutralization of input during web page generation.
