---
brief_id: brief-2026-11-09-jetformbuilder-xss
event_id: brief-2026-11-09-jetformbuilder-xss
revision: 1
activity_at: "2026-11-09T13:49:03Z"
title: 'Crocoblock JetFormBuilder: DOM-Based Cross-Site Scripting (CVE-2026-123484)'
slug: 2026-11-jetformbuilder-xss
description: A DOM-based cross-site scripting (XSS) vulnerability exists in Crocoblock JetFormBuilder due to improper neutralization of input during web page generation. This issue affects JetFormBuilder from version n/a through 3.6.8.
date: "2026-11-09T13:49:03Z"
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
  - cpe:2.3:a:crocoblock:jetformbuilder:*:*:*:*:*:*:*:*
vendors:
  - Crocoblock
products:
  - JetFormBuilder (<= 3.6.8)
cves:
  - id: CVE-2026-123484
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123484
---

Crocoblock JetFormBuilder (versions n/a through 3.6.8) is susceptible to a DOM-based cross-site scripting (XSS) vulnerability (CVE-2026-123484) caused by improper neutralization of input during web page generation.
