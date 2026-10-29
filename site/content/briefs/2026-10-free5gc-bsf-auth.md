---
brief_id: brief-2026-10-29-free5gc-bsf-auth
event_id: brief-2026-10-29-free5gc-bsf-auth
revision: 1
activity_at: "2026-10-29T21:24:54Z"
title: 'free5gc bsf: Missing authentication (CVE-2026-115926)'
slug: 2026-10-free5gc-bsf-auth
description: A public proof-of-concept exploit has been published for CVE-2026-115926, which involves a complete absence of authentication in the free5gc 'bsf' package.
date: "2026-10-29T21:24:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
vendors:
  - free5gc
products:
  - bsf
cves:
  - id: CVE-2026-115926
    cvss: 6
    kev_status: unknown
references:
  - https://github.com/free5gc/free5gc/security/advisories/GHSA-5wxg-mj2c-p9p2
  - https://sploitus.com/exploit?id=89F90BF4-8AA3-5BCC-A172-126472362A0D
  - https://sploitus.com/exploit?id=89F90BF4-8AA3-5BCC-A172-126472362A0D&utm_source=rss&utm_medium=rss
---

A public proof-of-concept exploit is available for CVE-2026-115926, a vulnerability identified as a complete absence of authentication in the free5gc 'bsf' package. The vulnerability is rated at 6.0 (Medium Severity).
