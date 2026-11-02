---
brief_id: brief-2026-11-02-wavlink-wn536ax6a-rce
event_id: brief-2026-11-02-wavlink-wn536ax6a-rce
revision: 2
activity_at: "2026-11-02T03:11:20Z"
revision_history:
  - revision: 2
    at: "2026-11-02T03:11:20Z"
    checksum: sha256:4b4bda7324fdd086537b88f1f3bb3226848a882419bd68dadf242c7d512c7bbe
    summary: poc_available; added CVE-2026-120282
    changed_fields:
      - affected_products
      - claim_state
      - cpes
      - cves
      - has_poc
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120282
title: 'WAVLINK WN536AX6-A: Remote command injection (CVE-2026-120276)'
slug: 2026-11-wavlink-wn536ax6a-rce
description: A remote OS command injection vulnerability exists in the WAVLINK WN536AX6-A router, version V260507_2.0.0.
date: "2026-11-02T01:01:37Z"
lastmod: "2026-11-02T03:10:34Z"
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
  - cpe:2.3:a:wavlink:wn536ax6_a:*:*:*:*:*:*:*:*
  - cpe:2.3:h:wavlink:wn536ax6-a:v260507_2.0.0:*:*:*:*:*:*:*
  - cpe:2.3:h:wavlink:wn536ax6-a:v260507:*:*:*:*:*:*:*
has_poc: true
tags:
  - RCE
  - Command Injection
vendors:
  - WAVLINK
products:
  - WN536AX6-A (V260507_2.0.0)
  - WN536AX6-A (V260507)
cves:
  - id: CVE-2026-120276
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-120277
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-120280
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-120281
    cvss: 10
    kev_status: "false"
  - id: CVE-2026-120282
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120276
  - CVE-2026-120277
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120277
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120280
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120281
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120282
updates:
  - at: "2026-11-02T01:01:50Z"
    level: L2
    summary: added CVE-2026-120277
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120277
  - at: "2026-11-02T03:10:26Z"
    level: L2
    summary: added CVE-2026-120280, CVE-2026-120281
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120280
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120281
  - at: "2026-11-02T03:10:34Z"
    level: L2
    summary: poc_available; added CVE-2026-120282
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120282
---

A weakness has been identified in the Web Management Interface of the WAVLINK WN536AX6-A (version V260507_2.0.0). The vulnerability resides in function 'sub_416760' of the file '/bin/ioos'. Manipulation of the 'group_name' argument allows for remote OS command injection. Public exploit code is available for this vulnerability. The vendor was contacted early regarding this disclosure.
