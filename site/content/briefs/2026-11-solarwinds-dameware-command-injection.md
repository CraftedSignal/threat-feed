---
brief_id: brief-2026-11-03-solarwinds-dameware-command-injection
event_id: brief-2026-11-03-solarwinds-dameware-command-injection
revision: 2
activity_at: "2026-11-03T21:28:45Z"
revision_history:
  - revision: 2
    at: "2026-11-03T21:28:45Z"
    checksum: sha256:82d789d7d4e82f31950d1b82d32514ac998352031accdfb826280a223685a16e
    summary: poc_available
    changed_fields:
      - affected_products
      - affected_vendors
      - claim_state
      - cpes
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-28336&utm_source=rss&utm_medium=rss
title: 'SolarWinds Dameware: Authenticated Command Injection (CVE-2026-28336)'
slug: 2026-11-solarwinds-dameware-command-injection
description: SolarWinds Dameware is affected by a command injection vulnerability requiring authentication that could lead to the compromise of the remotely controlled host.
date: "2026-11-03T20:01:59Z"
lastmod: "2026-11-03T21:27:53Z"
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
  - cpe:2.3:a:solarwinds:dameware:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-28336&utm_source=rss&utm_medium=rss
vendors:
  - SolarWinds
products:
  - Dameware
cves:
  - id: CVE-2026-28336
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28336
  - https://sploitus.com/exploit?id=CVE-2026-28336&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-03T21:27:53Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-28336&utm_source=rss&utm_medium=rss
---

SolarWinds Dameware was found to be affected by a command injection vulnerability (CVE-2026-28336) that could lead to the compromise of the remotely controlled host. Authentication is required to exploit this vulnerability. The CVSS v3.1 base score is 9.9.
