---
brief_id: brief-2026-11-05-path-traversal
event_id: brief-2026-11-05-path-traversal
revision: 2
activity_at: "2026-11-05T00:22:30Z"
revision_history:
  - revision: 2
    at: "2026-11-05T00:22:30Z"
    checksum: sha256:f4c65e91a4522707222d8ad1a23e866d6605016fa6036060e0545ada9dba3011
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-122013&utm_source=rss&utm_medium=rss
title: 'Comfast CF-WR632AX: Multipart Parser path traversal (CVE-2026-122013)'
slug: 2026-11-path-traversal
description: A path traversal vulnerability exists in the Multipart Parser component of the Comfast CF-WR632AX (2.6.0.1) router.
date: "2026-11-05T00:05:40Z"
lastmod: "2026-11-05T00:21:16Z"
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
cpes:
  - cpe:2.3:h:comfast:cf-wr632ax:2.6.0.1:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-122013&utm_source=rss&utm_medium=rss
vendors:
  - Comfast
products:
  - CF-WR632AX (2.6.0.1)
cves:
  - id: CVE-2026-122013
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122013
  - https://sploitus.com/exploit?id=CVE-2026-122013&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-05T00:21:16Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-122013&utm_source=rss&utm_medium=rss
---

A vulnerability has been identified in the Comfast CF-WR632AX firmware version 2.6.0.1. The issue resides in the /usr/bin/webmgnt component's Multipart Parser. By manipulating the 'filename' argument, an attacker can perform path traversal. The attack can be initiated remotely. The exploit is public, and the vendor has not responded to disclosure efforts.
