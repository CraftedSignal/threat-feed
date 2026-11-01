---
brief_id: brief-2026-10-26-oray-x5-pro-crlf
event_id: brief-2026-10-26-oray-x5-pro-crlf
revision: 5
activity_at: "2026-11-01T20:55:36Z"
revision_history:
  - revision: 2
    at: "2026-10-26T11:42:37Z"
    checksum: sha256:e6fa20aeb03e5817d77a31b89e795b7d68d02aaa56485a6098ae27992c6bf476
    summary: added CVE-2026-116232
    changed_fields:
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116232
  - revision: 3
    at: "2026-10-29T20:03:29Z"
    checksum: sha256:882563b6c164c2abd114766fce5e1998be4b27d4cd225be4b4b517089f0c07b5
    summary: added CVE-2026-116237
    changed_fields:
      - claim_state
      - cves
      - lastmod
      - priority_signals
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116237
  - revision: 4
    at: "2026-11-01T18:57:53Z"
    checksum: sha256:7c479dc01650dde57bb4f5621da4db0e014e5b8483afa449508ce0f12ef1f2c1
    summary: added CVE-2026-120224
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120224
  - revision: 5
    at: "2026-11-01T20:55:36Z"
    checksum: sha256:14d6b8c69c2ea7cbc7dcbb99cadcb75bd17da37942eabb7b3b8e9fd059e9598e
    summary: added CVE-2026-116235 +1
    changed_fields:
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120225
title: 'Oray Pugongying X5 Pro: CRLF injection in Ser2net (CVE-2026-116231)'
slug: 2026-10-oray-x5-pro-crlf
description: A security flaw in the Ser2net component of Oray Pugongying X5 Pro 7.6.1 allows for remote CRLF injection via manipulation of the regmsg argument.
date: "2026-10-26T09:40:17Z"
lastmod: "2026-11-01T20:54:51Z"
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
  - cpe:2.3:a:oray:pugongying_x5_pro:*:*:*:*:*:*:*:*
  - cpe:2.3:a:oray:pugongying_x5_pro:7.6.1:*:*:*:*:*:*:*
vendors:
  - Oray
products:
  - Oray Pugongying X5 Pro 7.6.1
  - Pugongying X5 Pro (7.6.1)
  - Pugongying X5 Pro (<= 7.6.1)
cves:
  - id: CVE-2026-116231
    cvss: 9.9
    epss: 0.00436
    kev_status: "false"
  - id: CVE-2026-116233
    cvss: 9.1
    epss: 0.00461
    kev_status: "false"
  - id: CVE-2026-116234
    cvss: 9.1
    epss: 0.00461
    kev_status: "false"
  - id: CVE-2026-116232
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-116237
    cvss: 8.4
    kev_status: unknown
  - id: CVE-2026-120224
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-120225
    cvss: 9.1
    kev_status: "false"
  - id: CVE-2026-116235
    cvss: 9.1
    epss: 0.00614
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116231
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116233
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116234
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116232
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116235
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116237
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120224
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120225
updates:
  - at: "2026-10-26T09:40:40Z"
    level: L2
    summary: added CVE-2026-116234
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116234
  - at: "2026-10-26T11:41:33Z"
    level: L2
    summary: added CVE-2026-116232
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116232
  - at: "2026-10-29T20:02:00Z"
    level: L2
    summary: added CVE-2026-116237
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116237
  - at: "2026-11-01T18:56:39Z"
    level: L2
    summary: added CVE-2026-120224
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120224
  - at: "2026-11-01T20:54:51Z"
    level: L2
    summary: added CVE-2026-116235 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120225
---

A security flaw has been identified in the Ser2net component of Oray Pugongying X5 Pro 7.6.1. Manipulation of the 'regmsg' argument results in CRLF injection. The attack can be initiated remotely. Public exploit code is available for this vulnerability. The vendor was contacted but did not respond.
