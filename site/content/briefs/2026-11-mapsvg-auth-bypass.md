---
brief_id: brief-2026-11-09-mapsvg-auth-bypass
event_id: brief-2026-11-09-mapsvg-auth-bypass
revision: 1
activity_at: "2026-11-09T11:42:55Z"
title: 'PT Norther Lights Production MapSVG: Missing authorization vulnerability (CVE-2026-123475)'
slug: 2026-11-mapsvg-auth-bypass
description: The PT Norther Lights Production MapSVG mapsvg-lite-interactive-vector-maps plugin contains a missing authorization vulnerability that allows for the exploitation of incorrectly configured access control security levels.
date: "2026-11-09T11:42:55Z"
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
  - cpe:2.3:a:pt_norther_lights_production:mapsvg:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - cve-2026-123475
vendors:
  - PT Norther Lights Production
products:
  - MapSVG (n/a through 8.16.3)
cves:
  - id: CVE-2026-123475
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123475
---

CVE-2026-123475 is a missing authorization vulnerability in the PT Norther Lights Production MapSVG mapsvg-lite-interactive-vector-maps plugin. This vulnerability allows for the exploitation of incorrectly configured access control security levels. This issue affects versions from n/a through 8.16.3.
