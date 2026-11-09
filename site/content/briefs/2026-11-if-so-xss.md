---
brief_id: brief-2026-11-09-if-so-xss
event_id: brief-2026-11-09-if-so-xss
revision: 1
activity_at: "2026-11-09T11:40:45Z"
title: 'If-So Dynamic Content Personalization: Reflected Cross-Site Scripting (CVE-2026-121782)'
slug: 2026-11-if-so-xss
description: The If-So Dynamic Content Personalization plugin contains an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability allowing Reflected XSS.
date: "2026-11-09T11:40:45Z"
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
products:
  - If-So Dynamic Content Personalization (n/a - 1.10.3)
cves:
  - id: CVE-2026-121782
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121782
---

The If-So Dynamic Content Personalization plugin (versions n/a through 1.10.3) is affected by a Reflected Cross-Site Scripting (XSS) vulnerability due to improper neutralization of input during web page generation.
