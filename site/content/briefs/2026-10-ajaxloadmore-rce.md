---
brief_id: brief-2026-10-29-ajaxloadmore-rce
event_id: brief-2026-10-29-ajaxloadmore-rce
revision: 2
activity_at: "2026-10-29T20:21:52Z"
revision_history:
  - revision: 2
    at: "2026-10-29T20:21:52Z"
    checksum: sha256:0c0cfdad5b0087cffdc08d2da2df4fc3498e1821b1cbe131bc7e0a06b5003bef
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
      - https://sploitus.com/exploit?id=CVE-2026-61991&utm_source=rss&utm_medium=rss
title: 'AjaxLoadMore Cache: Unauthenticated remote code execution (CVE-2026-61991)'
slug: 2026-10-ajaxloadmore-rce
description: AjaxLoadMore Cache versions 3.1.1 and earlier contain an unauthenticated remote code execution vulnerability.
date: "2026-10-29T17:40:12Z"
lastmod: "2026-10-29T20:20:54Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-61991&utm_source=rss&utm_medium=rss
vendors:
  - WordPress
cves:
  - id: CVE-2026-61991
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61991
  - https://sploitus.com/exploit?id=CVE-2026-61991&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-29T20:20:54Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-61991&utm_source=rss&utm_medium=rss
---

AjaxLoadMore Cache versions 3.1.1 and earlier are affected by an unauthenticated remote code execution (RCE) vulnerability (CVE-2026-61991). This vulnerability carries a CVSS v3.1 base score of 10.0.
