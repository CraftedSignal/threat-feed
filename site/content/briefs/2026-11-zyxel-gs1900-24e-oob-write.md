---
brief_id: brief-2026-11-03-zyxel-gs1900-24e-oob-write
event_id: brief-2026-11-03-zyxel-gs1900-24e-oob-write
revision: 2
activity_at: "2026-11-03T04:05:53Z"
revision_history:
  - revision: 2
    at: "2026-11-03T04:05:53Z"
    checksum: sha256:91e4c05562b77df30716736c2209223a93a0a5b6d4e2abf4fefa70ea6d9723e9
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
title: 'Zyxel GS1900-24E: Out-of-bounds write vulnerability (CVE-2026-107441)'
slug: 2026-11-zyxel-gs1900-24e-oob-write
description: An out-of-bounds write vulnerability in the CGI program of Zyxel GS1900-24E firmware versions through 2.90(AAHK.2)C0 could allow an unauthenticated adjacent attacker to potentially execute OS commands via a crafted HTTP request.
date: "2026-11-03T03:50:17Z"
lastmod: "2026-11-03T04:05:16Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:zyxel:gs1900_24e:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
vendors:
  - Zyxel
products:
  - GS1900-24E (through firmware 2.90(AAHK.2)C0)
cves:
  - id: CVE-2026-107441
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107441
  - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-03T04:05:16Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-107441&utm_source=rss&utm_medium=rss
---

An out-of-bounds write vulnerability exists in the CGI program of Zyxel GS1900-24E firmware versions through 2.90(AAHK.2)C0. This flaw may allow an unauthenticated adjacent attacker to potentially execute OS commands via a crafted HTTP request. The vulnerability is identified as CVE-2026-107441 with a CVSS v3.1 base score of 8.8.
