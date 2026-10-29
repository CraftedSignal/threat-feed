---
brief_id: brief-2026-10-29-oceanwp-xss
event_id: brief-2026-10-29-oceanwp-xss
revision: 1
activity_at: "2026-10-29T17:35:54Z"
title: 'OceanWP: Reflected Cross-site Scripting (CVE-2026-115592)'
slug: 2026-10-oceanwp-xss
description: A reflected cross-site scripting vulnerability exists in the OceanWP theme for WordPress due to improper neutralization of input during web page generation.
date: "2026-10-29T17:35:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:oceanwp:oceanwp:*:*:*:*:*:*:*:*
vendors:
  - OceanWP
products:
  - OceanWP
cves:
  - id: CVE-2026-115592
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115592
---

CVE-2026-115592 is a Reflected Cross-site Scripting (XSS) vulnerability affecting OceanWP. The issue is caused by the improper neutralization of input during web page generation. This vulnerability affects OceanWP from version n/a through 4.2.7.

## Impact
Successful exploitation allows for Reflected XSS.

## References
- https://nvd.nist.gov/vuln/detail/CVE-2026-115592
