---
brief_id: brief-2026-11-09-form-maker-xss-45f0b3c4
event_id: brief-2026-11-09-form-maker-xss-45f0b3c4
revision: 1
activity_at: "2026-11-09T11:39:04Z"
title: 'Form Maker by 10Web: Stored cross-site scripting (CVE-2026-119483)'
slug: 2026-11-form-maker-xss-45f0b3c4
description: A stored cross-site scripting (XSS) vulnerability in Form Maker by 10Web allows improper neutralization of input during web page generation.
date: "2026-11-09T11:39:04Z"
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
  - cpe:2.3:a:10web:form_maker:*:*:*:*:*:*:*:*
vendors:
  - 10Web
products:
  - Form Maker by 10Web (n/a through 1.15.50)
cves:
  - id: CVE-2026-119483
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119483
---

The Form Maker by 10Web plugin contains a stored cross-site scripting (XSS) vulnerability caused by improper neutralization of input during web page generation. This issue affects Form Maker by 10Web versions from n/a through 1.15.50.
