---
brief_id: brief-2026-10-25-geo-my-wp-lfi
event_id: brief-2026-10-25-geo-my-wp-lfi
revision: 1
activity_at: "2026-10-25T00:37:57Z"
title: 'GEO my WP: Unauthenticated Local File Inclusion (CVE-2024-6330)'
slug: 2026-10-geo-my-wp-lfi
description: The GEO my WP WordPress plugin (versions <= 4.5.0.1) is vulnerable to unauthenticated local file inclusion (LFI) and arbitrary PHP code execution via the 'form[info_window_template][content_path]' parameter. A public exploit PoC has been published.
date: "2026-10-25T00:37:57Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RANDOMROBBIEBF-CVE-2024-6330
  observed_at: "2026-09-19T00:00:00Z"
  confidence: high
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
cpes:
  - cpe:2.3:a:geomywp:geo_my_wordpress:*:*:*:*:*:wordpress:*:*
products:
  - GEO my WP (<= 4.5.0.1)
cves:
  - id: CVE-2024-6330
    cvss: 9.8
    epss: 0.02143
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RANDOMROBBIEBF-CVE-2024-6330
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RANDOMROBBIEBF-CVE-2024-6330&utm_source=rss&utm_medium=rss
---
