---
brief_id: brief-2026-10-29-instawp-csrf
event_id: brief-2026-10-29-instawp-csrf
revision: 1
activity_at: "2026-10-29T15:40:14Z"
title: 'InstaWP Connect: Cross-Site Request Forgery (CVE-2026-116399)'
slug: 2026-10-instawp-csrf
description: InstaWP Connect versions n/a through 0.1.4.2 are affected by a Cross-Site Request Forgery (CSRF) vulnerability.
date: "2026-10-29T15:40:14Z"
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
  - cpe:2.3:a:instawp:connect:*:*:*:*:*:*:*:*
vendors:
  - InstaWP
products:
  - InstaWP Connect (n/a through 0.1.4.2)
cves:
  - id: CVE-2026-116399
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116399
---

A Cross-Site Request Forgery (CSRF) vulnerability exists in the InstaWP Connect plugin for WordPress, affecting versions n/a through 0.1.4.2. The vulnerability has a CVSS v3.1 base score of 8.8.
