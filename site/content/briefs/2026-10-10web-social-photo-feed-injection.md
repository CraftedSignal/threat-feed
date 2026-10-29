---
brief_id: brief-2026-10-29-10web-social-photo-feed-injection
event_id: brief-2026-10-29-10web-social-photo-feed-injection
revision: 1
activity_at: "2026-10-29T20:39:58Z"
title: '10Web Social Photo Feed: PHP object injection (CVE-2026-118081)'
slug: 2026-10-10web-social-photo-feed-injection
description: The 10Web Social Photo Feed plugin versions 1.5.6 and earlier contain a contributor-level PHP object injection vulnerability.
date: "2026-10-29T20:39:58Z"
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
  - cpe:2.3:a:10web:social_photo_feed:*:*:*:*:*:*:*:*
vendors:
  - 10Web
products:
  - Social Photo Feed (<= 1.5.6)
cves:
  - id: CVE-2026-118081
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118081
---

CVE-2026-118081 identifies a PHP object injection vulnerability in 10Web Social Photo Feed versions 1.5.6 and lower. This vulnerability is accessible to users with contributor-level permissions.
