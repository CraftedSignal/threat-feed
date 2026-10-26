---
brief_id: brief-2026-10-23-php-session-injection
event_id: brief-2026-10-23-php-session-injection
revision: 2
activity_at: "2026-10-26T16:14:36Z"
revision_history:
  - revision: 2
    at: "2026-10-26T16:14:36Z"
    checksum: sha256:c4e7133067501dc79cc237be71719bc4aeb21b4cc433db1f6ceb319904e2bbe6
    summary: new product
    changed_fields:
      - affected_products
      - affected_vendors
      - lastmod
      - references
      - updates
    source_urls:
      - https://socprime.com/blog/cve-2026-115560-new-unpatched-php-rce-risk-requires-immediate-mitigation/
title: 'PHP: Session Upload Progress Injection (CVE-2026-115560)'
slug: 2026-10-php-session-injection
description: Public proof-of-concept exploit code has been published for CVE-2026-115560, identified as a PHP Session Upload Progress Injection vulnerability.
date: "2026-10-23T17:43:39Z"
lastmod: "2026-10-26T16:13:32Z"
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
  - PHP
products:
  - PHP
cves:
  - id: CVE-2026-115560
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=21ECC387-5A3C-5E76-A26E-F5872215776E
  - https://sploitus.com/exploit?id=21ECC387-5A3C-5E76-A26E-F5872215776E&utm_source=rss&utm_medium=rss
  - https://socprime.com/blog/cve-2026-115560-new-unpatched-php-rce-risk-requires-immediate-mitigation/
updates:
  - at: "2026-10-26T16:13:32Z"
    level: L1
    summary: new product
    sources:
      - socprime
    source_urls:
      - https://socprime.com/blog/cve-2026-115560-new-unpatched-php-rce-risk-requires-immediate-mitigation/
---

Public proof-of-concept exploit code for CVE-2026-115560 has been released on Sploitus. The vulnerability is described as a PHP Session Upload Progress Injection.
