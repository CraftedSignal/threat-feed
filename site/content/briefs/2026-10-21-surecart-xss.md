---
brief_id: brief-2026-10-21-surecart-xss
event_id: brief-2026-10-21-surecart-xss
revision: 1
activity_at: "2026-10-21T16:09:14Z"
title: 'Brainstorm Force SureCart: Stored Cross-Site Scripting (CVE-2026-112221)'
slug: 2026-10-21-surecart-xss
description: A stored cross-site scripting (XSS) vulnerability in the Brainstorm Force SureCart plugin (versions 4.9.5 and earlier) due to improper neutralization of input during web page generation.
date: "2026-10-21T16:09:14Z"
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
  - cpe:2.3:a:brainstorm_force:surecart:*:*:*:*:*:*:*:*
vendors:
  - Brainstorm Force
products:
  - SureCart (n/a through 4.9.5)
cves:
  - id: CVE-2026-112221
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112221
---

The Brainstorm Force SureCart plugin for WordPress, in versions from n/a through 4.9.5, contains a vulnerability involving the improper neutralization of input during web page generation, which allows for Stored XSS.
