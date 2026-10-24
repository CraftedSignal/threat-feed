---
brief_id: brief-2026-10-24-tribulant-sqli
event_id: brief-2026-10-24-tribulant-sqli
revision: 2
activity_at: "2026-10-24T11:14:07Z"
revision_history:
  - revision: 2
    at: "2026-10-24T11:14:07Z"
    checksum: sha256:8d1bca7550d146953d62ec32b99a8dab54f2ad60e5d63b4dec175783f135bfa9
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-111402&utm_source=rss&utm_medium=rss
title: Tribulant Software Newsletters SQL injection (CVE-2026-111402)
slug: 2026-10-tribulant-sqli
description: Tribulant Software Newsletters newsletters-lite contains an 'Improper Neutralization of Special Elements used in an SQL Command' (SQL Injection) vulnerability.
date: "2026-10-24T10:11:43Z"
lastmod: "2026-10-24T11:13:07Z"
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
cpes:
  - cpe:2.3:a:tribulant_software:newsletters:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-111402&utm_source=rss&utm_medium=rss
vendors:
  - Tribulant Software
products:
  - Newsletters (n/a through 4.18.1)
cves:
  - id: CVE-2026-111402
    cvss: 9.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111402
  - https://sploitus.com/exploit?id=CVE-2026-111402&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-10-24T11:13:07Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-111402&utm_source=rss&utm_medium=rss
---

Tribulant Software Newsletters (newsletters-lite) is affected by an Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) vulnerability. This issue affects Newsletters from n/a through 4.18.1.
