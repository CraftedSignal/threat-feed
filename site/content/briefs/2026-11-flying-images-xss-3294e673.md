---
brief_id: brief-2026-11-09-flying-images-xss-3294e673
event_id: brief-2026-11-09-flying-images-xss-3294e673
revision: 1
activity_at: "2026-11-09T11:39:50Z"
title: 'Gijo Varghese Flying Images: Stored Cross-Site Scripting (CVE-2026-121780)'
slug: 2026-11-flying-images-xss-3294e673
description: The Flying Images plugin (versions n/a through 2.4.15) contains a Stored Cross-site Scripting (XSS) vulnerability due to improper neutralization of input during web page generation.
date: "2026-11-09T11:39:50Z"
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
  - cpe:2.3:a:gijo_varghese:flying_images:*:*:*:*:*:*:*:*
vendors:
  - Gijo Varghese
products:
  - Flying Images (<= 2.4.15)
cves:
  - id: CVE-2026-121780
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121780
---

The Gijo Varghese Flying Images plugin is vulnerable to Stored Cross-site Scripting (XSS). This vulnerability exists due to improper neutralization of input during web page generation. The issue affects all versions from n/a through 2.4.15.
