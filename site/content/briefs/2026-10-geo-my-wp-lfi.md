---
brief_id: brief-2026-10-25-geo-my-wp-lfi
event_id: brief-2026-10-25-geo-my-wp-lfi
revision: 2
activity_at: "2026-11-21T22:51:18Z"
revision_history:
  - revision: 2
    at: "2026-11-21T22:51:18Z"
    checksum: sha256:c0c68cf73b378516ae608080c6551d0e58d4437c91febbe75f48027e907ffcb7
    summary: Updated content, exploitation_evidence, lastmod, priority_signals, references, severity, source_assessment, summary
    changed_fields:
      - content
      - exploitation_evidence
      - lastmod
      - priority_signals
      - references
      - severity
      - source_assessment
      - summary
title: 'GEO my WP: Unauthenticated Local File Inclusion (CVE-2024-6330)'
slug: 2026-10-geo-my-wp-lfi
description: The GEO my WP WordPress plugin before version 4.5.0.2 allows unauthenticated attackers to include arbitrary files in PHP execution context, leading to remote code execution.
date: "2026-10-25T00:37:57Z"
lastmod: "2026-11-21T22:50:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: unlikely
cpes:
  - cpe:2.3:a:geomywp:geo_my_wordpress:*:*:*:*:*:wordpress:*:*
products:
  - GEO my WP
product_versions:
  - product: GEO my WP
    range: <= 4.5.0.1
cves:
  - id: CVE-2024-6330
    cvss: 9.8
    epss: 0.02143
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-6330
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-RANDOMROBBIEBF-CVE-2024-6330
---

## Impact
NVD states that GEO my WP versions before 4.5.0.2 allow unauthenticated arbitrary file inclusion in PHP execution context, which can lead to remote code execution.

## Recommendation
Update GEO my WP to version 4.5.0.2 or later.
