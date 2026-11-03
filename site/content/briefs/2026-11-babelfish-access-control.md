---
brief_id: brief-2026-11-03-babelfish-access-control
event_id: brief-2026-11-03-babelfish-access-control
revision: 2
activity_at: "2026-11-03T21:28:45Z"
revision_history:
  - revision: 2
    at: "2026-11-03T21:28:45Z"
    checksum: sha256:90137498f578362061dc6921cbb4cba426e8e28774c691b2c27cd0ad136d2531
    summary: poc_available
    changed_fields:
      - affected_vendors
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-119922&utm_source=rss&utm_medium=rss
title: 'Babelfish for PostgreSQL: Improper access control vulnerability (CVE-2026-119922)'
slug: 2026-11-babelfish-access-control
description: An improper access control vulnerability in Babelfish for PostgreSQL versions 1.2-1.5, 2.1-2.15, 3.1-3.12, 4.0-4.8, and 5.1-5.4 may allow remote authenticated users to elevate their privileges.
date: "2026-11-03T20:02:33Z"
lastmod: "2026-11-03T21:27:52Z"
type: advisory
claim_state: <nil>
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
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-119922&utm_source=rss&utm_medium=rss
vendors:
  - Amazon
cves:
  - id: CVE-2026-119922
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119922
  - https://sploitus.com/exploit?id=CVE-2026-119922&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-03T21:27:52Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-119922&utm_source=rss&utm_medium=rss
---

Babelfish for PostgreSQL versions 1.2-1.5, 2.1-2.15, 3.1-3.12, 4.0-4.8, and 5.1-5.4 contain an improper access control vulnerability (CVE-2026-119922) that may allow remote authenticated users to elevate their privileges. The CVSS v3.1 base score for this vulnerability is 8.8. To remediate this issue, it is recommended to upgrade to Babelfish for PostgreSQL extension versions 4.10, 5.6, 6.1 or later.
