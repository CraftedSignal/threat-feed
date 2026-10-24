---
brief_id: brief-2026-10-24-tribulant-newsletters-deserialization
event_id: brief-2026-10-24-tribulant-newsletters-deserialization
revision: 2
activity_at: "2026-10-24T11:14:07Z"
revision_history:
  - revision: 2
    at: "2026-10-24T11:14:07Z"
    checksum: sha256:2f4612a0e2e0207e6fc0d27c0a4b00077cdc4487e2a61a3f55fbff54961b816c
    summary: poc_available
    changed_fields:
      - affected_vendors
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-94075&utm_source=rss&utm_medium=rss
title: 'Tribulant Software Newsletters: Deserialization of Untrusted Data (CVE-2026-94075)'
slug: 2026-10-tribulant-newsletters-deserialization
description: A Deserialization of Untrusted Data vulnerability exists in Tribulant Software Newsletters (newsletters-lite) from version n/a through 4.18.1, allowing Object Injection.
date: "2026-10-24T10:12:59Z"
lastmod: "2026-10-24T11:13:06Z"
type: advisory
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
  - https://sploitus.com/exploit?id=CVE-2026-94075&utm_source=rss&utm_medium=rss
vendors:
  - Tribulant Software
cves:
  - id: CVE-2026-94075
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94075
  - https://sploitus.com/exploit?id=CVE-2026-94075&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-24T11:13:06Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-94075&utm_source=rss&utm_medium=rss
---

Tribulant Software Newsletters (newsletters-lite) is affected by a Deserialization of Untrusted Data vulnerability (CVE-2026-94075). This issue allows for Object Injection. The vulnerability affects versions from n/a through 4.18.1 and carries a CVSS v3.1 base score of 9.8.
