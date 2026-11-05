---
brief_id: brief-2026-11-05-edimax-command-injection
event_id: brief-2026-11-05-edimax-command-injection
revision: 2
activity_at: "2026-11-05T07:46:27Z"
revision_history:
  - revision: 2
    at: "2026-11-05T07:46:27Z"
    checksum: sha256:52d7d638b34f5d8162e7f2326ffa3afea160f9b85cc6b38794c7961b8e63cc1c
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=50E2C26C-3636-57F2-807D-0A6C15AEA2D4&utm_source=rss&utm_medium=rss
title: 'Edimax BR-6208AC: Command injection via /goform/mp (CVE-2026-122051)'
slug: 2026-11-edimax-command-injection
description: A flaw in the Edimax BR-6208AC version 1.32, specifically in the /goform/mp file, allows for command injection that may be launched remotely. The vendor has not responded to disclosure attempts.
date: "2026-11-05T01:18:30Z"
lastmod: "2026-11-05T07:39:31Z"
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
  - cpe:2.3:a:edimax:br_6208ac:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=50E2C26C-3636-57F2-807D-0A6C15AEA2D4&utm_source=rss&utm_medium=rss
vendors:
  - Edimax
products:
  - BR-6208AC (1.32)
cves:
  - id: CVE-2026-122051
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-122051
  - https://sploitus.com/exploit?id=50E2C26C-3636-57F2-807D-0A6C15AEA2D4&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-05T07:39:31Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=50E2C26C-3636-57F2-807D-0A6C15AEA2D4&utm_source=rss&utm_medium=rss
---

CVE-2026-122051 is a command injection vulnerability affecting the Edimax BR-6208AC router, version 1.32. The flaw exists in the /goform/mp file. The attack can be launched remotely, and a public exploit exists. The vendor was contacted but did not respond. The CVSS v3.1 base score is 10.0.
