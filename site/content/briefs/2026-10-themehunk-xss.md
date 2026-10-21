---
brief_id: brief-2026-10-21-themehunk-xss
event_id: brief-2026-10-21-themehunk-xss
revision: 1
activity_at: "2026-10-21T16:08:42Z"
title: 'ThemeHunk Customizer: Reflected Cross-Site Scripting (CVE-2026-111838)'
slug: 2026-10-themehunk-xss
description: ThemeHunk Customizer versions from n/a through 2.8.7 are affected by a Reflected Cross-site Scripting (XSS) vulnerability due to improper neutralization of input during web page generation.
date: "2026-10-21T16:08:42Z"
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
  - cpe:2.3:a:themehunk:customizer:*:*:*:*:*:*:*:*
vendors:
  - ThemeHunk
products:
  - ThemeHunk Customizer (n/a through 2.8.7)
cves:
  - id: CVE-2026-111838
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111838
---

ThemeHunk Customizer (versions up to 2.8.7) contains an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability. This vulnerability allows for Reflected XSS.
