---
brief_id: brief-2026-11-11-xapi-timing-side-channel
event_id: brief-2026-11-11-xapi-timing-side-channel
revision: 1
activity_at: "2026-11-11T01:38:26Z"
title: 'Xen Project: XAPI Pool Secret comparison vulnerability (CVE-2026-102705)'
slug: 2026-11-xapi-timing-side-channel
description: The Xen Project has disclosed that the XAPI component, which uses a Pool Secret for authenticating requests between hosts in a pool, performs token comparisons using a data-dependent function.
date: "2026-11-11T01:38:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: unknown
vendors:
  - Xen
products:
  - XAPI
cves:
  - id: CVE-2026-102705
    kev_status: unknown
references:
  - https://xenbits.xen.org/xsa/advisory-529.html
  - https://seclists.org/oss-sec/2026/q4/641
---

Xen Security Advisory XSA-529 identifies that the XAPI component uses a data-dependent comparison function for the Pool Secret, a bearer token used to authenticate requests between hosts in a pool.
