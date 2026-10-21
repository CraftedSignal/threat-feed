---
brief_id: brief-2026-10-21-geo-mashup-xss
event_id: brief-2026-10-21-geo-mashup-xss
revision: 1
activity_at: "2026-10-21T16:08:57Z"
title: 'Geo Mashup: Reflected Cross-site Scripting (CVE-2026-111848)'
slug: 2026-10-geo-mashup-xss
description: The Geo Mashup software by Dylan Kuhn is vulnerable to Reflected Cross-site Scripting (XSS) due to improper neutralization of input during web page generation.
date: "2026-10-21T16:08:57Z"
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
  - cpe:2.3:a:dylan_kuhn:geo_mashup:*:*:*:*:*:*:*:*
vendors:
  - Dylan Kuhn
products:
  - Geo Mashup (n/a through 1.13.22)
cves:
  - id: CVE-2026-111848
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111848
---

The Geo Mashup software (versions from n/a through 1.13.22) contains an Improper Neutralization of Input During Web Page Generation vulnerability, identified as Cross-site Scripting (XSS).
