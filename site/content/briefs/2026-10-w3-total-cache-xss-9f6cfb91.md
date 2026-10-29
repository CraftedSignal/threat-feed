---
brief_id: brief-2026-10-29-w3-total-cache-xss-9f6cfb91
event_id: brief-2026-10-29-w3-total-cache-xss-9f6cfb91
revision: 1
activity_at: "2026-10-29T20:01:23Z"
title: 'Bold Grid W3 Total Cache: Stored Cross-site Scripting (CVE-2026-114178)'
slug: 2026-10-w3-total-cache-xss-9f6cfb91
description: Bold Grid W3 Total Cache versions from n/a through 2.10.7 contain an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability, which allows Stored XSS.
date: "2026-10-29T20:01:23Z"
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
  - cpe:2.3:a:bold_grid:w3_total_cache:*:*:*:*:*:*:*:*
vendors:
  - Bold Grid
products:
  - W3 Total Cache (n/a through 2.10.7)
cves:
  - id: CVE-2026-114178
    cvss: 7.1
    epss: 0.00205
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114178
---

Bold Grid W3 Total Cache is affected by an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability. The issue allows Stored XSS and affects versions from n/a through 2.10.7.

## Technical Details
- Vulnerability Type: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- Impact: Stored XSS
- CVSS v3.1 Base Score: 7.1
