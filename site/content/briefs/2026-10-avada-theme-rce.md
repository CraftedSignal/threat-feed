---
brief_id: brief-2026-10-29-avada-theme-rce
event_id: brief-2026-10-29-avada-theme-rce
revision: 1
activity_at: "2026-10-29T14:37:50Z"
title: 'Theme-fusion Avada: Unauthenticated arbitrary shortcode execution (CVE-2024-13346)'
slug: 2026-10-avada-theme-rce
description: CVE-2024-13346 affects Theme-fusion Avada versions prior to 7.11.14, allowing unauthenticated arbitrary shortcode execution. A public exploit is available.
date: "2026-10-29T14:37:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:theme-fusion:avada:*:*:*:*:*:wordpress:*:*
vendors:
  - Theme-fusion
products:
  - Avada (< 7.11.14)
cves:
  - id: CVE-2024-13346
    cvss: 7.3
    epss: 0.02297
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TAUSIFZAMAN-CVE-2024-13346
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TAUSIFZAMAN-CVE-2024-13346&utm_source=rss&utm_medium=rss
---

CVE-2024-13346 allows unauthenticated arbitrary shortcode execution in Theme-fusion Avada versions prior to 7.11.14. A public exploit or PoC has been published on Sploitus. The vulnerability has a CVSS score of 9.8 and an EPSS score of 2.3%.
