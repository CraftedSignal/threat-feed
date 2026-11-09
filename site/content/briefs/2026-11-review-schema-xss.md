---
brief_id: brief-2026-11-09-review-schema-xss
event_id: brief-2026-11-09-review-schema-xss
revision: 1
activity_at: "2026-11-09T11:40:14Z"
title: 'Review Schema: Reflected Cross-Site Scripting (CVE-2026-54863)'
slug: 2026-11-review-schema-xss
description: The Review Schema plugin by Mamunur Rashid (versions up to 3.1.4) is vulnerable to Reflected Cross-Site Scripting (XSS) due to improper neutralization of input during web page generation.
date: "2026-11-09T11:40:14Z"
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
  - cpe:2.3:a:mamunur_rashid:review_schema:*:*:*:*:*:*:*:*
vendors:
  - Mamunur Rashid
products:
  - Review Schema (n/a - 3.1.4)
cves:
  - id: CVE-2026-54863
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54863
---

The Review Schema plugin (versions n/a through 3.1.4) contains an Improper Neutralization of Input During Web Page Generation vulnerability, identified as Reflected Cross-Site Scripting (XSS).
