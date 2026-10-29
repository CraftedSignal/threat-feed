---
brief_id: brief-2026-10-29-meals-wheels-php-injection
event_id: brief-2026-10-29-meals-wheels-php-injection
revision: 1
activity_at: "2026-10-29T17:40:46Z"
title: 'Meals & Wheels: PHP object injection vulnerability (CVE-2026-62002)'
slug: 2026-10-meals-wheels-php-injection
description: Meals & Wheels versions 1.1.13 and earlier are vulnerable to unauthenticated PHP object injection.
date: "2026-10-29T17:40:46Z"
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
products:
  - Meals & Wheels (<= 1.1.13)
cves:
  - id: CVE-2026-62002
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62002
---

Meals & Wheels versions 1.1.13 and earlier contain an unauthenticated PHP object injection vulnerability (CVE-2026-62002). The CVSS v3.1 base score for this vulnerability is 9.8.
