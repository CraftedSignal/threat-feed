---
brief_id: brief-2026-10-29-geo-my-wordpress-php-injection
event_id: brief-2026-10-29-geo-my-wordpress-php-injection
revision: 1
activity_at: "2026-10-29T20:40:07Z"
title: 'GEO my WordPress: Unauthenticated PHP Object Injection (CVE-2026-61992)'
slug: 2026-10-geo-my-wordpress-php-injection
description: The GEO my WordPress plugin (versions 4.5.5.3 and earlier) is vulnerable to unauthenticated PHP object injection.
date: "2026-10-29T20:40:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:geo_my_wordpress:geo_my_wordpress:*:*:*:*:*:*:*:*
vendors:
  - GEO my WordPress
products:
  - GEO my WordPress (<= 4.5.5.3)
cves:
  - id: CVE-2026-61992
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61992
---

GEO my WordPress versions 4.5.5.3 and earlier contain an unauthenticated PHP object injection vulnerability.

## Impact
The vulnerability has a CVSS v3.1 base score of 9.8.
