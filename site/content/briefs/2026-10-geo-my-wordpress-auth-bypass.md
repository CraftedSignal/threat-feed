---
brief_id: brief-2026-10-29-geo-my-wordpress-auth-bypass
event_id: brief-2026-10-29-geo-my-wordpress-auth-bypass
revision: 1
activity_at: "2026-10-29T13:20:05Z"
title: 'GEO my WordPress: Missing authorization vulnerability (CVE-2026-114193)'
slug: 2026-10-geo-my-wordpress-auth-bypass
description: A missing authorization vulnerability in the Eyal Fitoussi GEO my WordPress plugin allows for the exploitation of incorrectly configured access control security levels.
date: "2026-10-29T13:20:05Z"
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
  - cpe:2.3:a:eyal_fitoussi:geo_my_wordpress:*:*:*:*:*:*:*:*
vendors:
  - Eyal Fitoussi
products:
  - GEO my WordPress (n/a through 4.5.5.5)
cves:
  - id: CVE-2026-114193
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114193
---

The GEO my WordPress plugin is affected by a missing authorization vulnerability (CVE-2026-114193) which allows for the exploitation of incorrectly configured access control security levels. This issue affects versions from n/a through 4.5.5.5.
