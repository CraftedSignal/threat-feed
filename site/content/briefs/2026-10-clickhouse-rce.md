---
brief_id: brief-2026-10-30-clickhouse-rce
event_id: brief-2026-10-30-clickhouse-rce
revision: 2
activity_at: "2026-10-30T16:52:53Z"
revision_history:
  - revision: 2
    at: "2026-10-30T16:52:53Z"
    checksum: sha256:d9cf20d0504ee721047dd78a1554c5a2d1d51122f41cd9edb834fbc1cc9d18ea
    summary: new vendor
    changed_fields:
      - affected_vendors
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/clickhouse-server-unauth-rce-cve-2026-116366
title: 'ClickHouse Server: Unauthenticated remote code execution (CVE-2026-116366)'
slug: 2026-10-clickhouse-rce
description: CVE-2026-116366 is a high-severity vulnerability in ClickHouse Server that allows an unauthenticated user with network access to execute arbitrary code.
date: "2026-10-30T13:42:01Z"
lastmod: "2026-10-30T16:52:19Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://sploitus.com/exploit?id=CVE-2026-116366
  observed_at: "2026-10-30T11:24:00Z"
  confidence: high
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
vendors:
  - ClickHouse
cves:
  - id: CVE-2026-116366
    kev_status: "false"
references:
  - https://github.com/ClickHouse/ClickHouse/blob/master/SECURITY.md
  - https://clickhouse.com/docs/resources/changelogs/security-changelog
  - https://sploitus.com/exploit?id=CVE-2026-116366
  - https://sploitus.com/exploit?id=CVE-2026-116366&utm_source=rss&utm_medium=rss
  - https://pwn.watch/i/clickhouse-server-unauth-rce-cve-2026-116366
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116366
updates:
  - at: "2026-10-30T16:52:19Z"
    level: L1
    summary: new vendor
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/clickhouse-server-unauth-rce-cve-2026-116366
---

An issue has been discovered in ClickHouse Server that, under certain conditions, could allow an unauthenticated user with network access to execute arbitrary code on the server. The vulnerability is reported with a CVSS 4.0 score of 9.5 and a high-severity rating.
