---
brief_id: brief-2026-11-05-cendio-thinlinc-auth-bypass
event_id: brief-2026-11-05-cendio-thinlinc-auth-bypass
revision: 1
activity_at: "2026-11-05T16:21:01Z"
title: 'Cendio ThinLinc: Improper authentication in web client (CVE-2026-119744)'
slug: 2026-11-cendio-thinlinc-auth-bypass
description: Cendio ThinLinc versions 4.1.0 through 4.20.0 contain an improper authentication vulnerability in the browser-based web client (tlwebaccess) that allows an authenticated attacker to impersonate other users, including root.
date: "2026-11-05T16:21:01Z"
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
  - cpe:2.3:a:cendio:thinlinc:*:*:*:*:*:*:*:*
vendors:
  - Cendio
products:
  - ThinLinc (4.1.0 through 4.20.0)
cves:
  - id: CVE-2026-119744
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119744
---

Cendio ThinLinc versions 4.1.0 through 4.20.0 contain an improper authentication vulnerability in its browser-based web client (tlwebaccess). An authenticated attacker can impersonate any other user, including root, by exploiting flaws in multi-step authentication flows such as one-time passwords, login banners, or expired password prompts.
