---
brief_id: brief-2026-11-01-wavlink-rce-df64a306
event_id: brief-2026-11-01-wavlink-rce-df64a306
revision: 3
activity_at: "2026-11-02T01:02:22Z"
revision_history:
  - revision: 2
    at: "2026-11-01T18:57:53Z"
    checksum: sha256:e773e51ef9ed63aef5712fb79dfb44db132b8a1c80997dd6fd7c1383ac44de2c
    summary: added CVE-2026-120238
    changed_fields:
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120238
  - revision: 3
    at: "2026-11-02T01:02:22Z"
    checksum: sha256:92733bc79cef9a7ef426cb8018b02f4e645775db31487a0e90d449bc1aa091bb
    summary: added CVE-2026-120240
    changed_fields:
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120240
title: 'WAVLINK WN553X1-B: OS command injection (CVE-2026-120231)'
slug: 2026-11-wavlink-rce-df64a306
description: A vulnerability in the OpenVPN CLI Handler component of the WAVLINK WN553X1-B (firmware V260403_2.0.0) allows remote OS command injection via the 'file_id' argument.
date: "2026-11-01T16:57:01Z"
lastmod: "2026-11-02T01:01:34Z"
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
  - cpe:2.3:a:wavlink:wn553x1_b:*:*:*:*:*:*:*:*
vendors:
  - WAVLINK
products:
  - WN553X1-B (V260403_2.0.0)
  - WN553X1-B (260403_2.0.0)
cves:
  - id: CVE-2026-120231
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-120238
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-120240
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120231
  - CVE-2026-120238
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120238
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120240
updates:
  - at: "2026-11-01T18:56:52Z"
    level: L2
    summary: added CVE-2026-120238
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120238
  - at: "2026-11-02T01:01:34Z"
    level: L2
    summary: added CVE-2026-120240
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120240
---

A vulnerability (CVE-2026-120231) has been identified in WAVLINK WN553X1-B firmware version V260403_2.0.0. The flaw is located in the function 'sub_416568' of the file '/bin/ioos' within the OpenVPN CLI Handler component. Manipulation of the 'file_id' argument results in OS command injection. The attack can be initiated remotely. Publicly disclosed exploit code exists and may be utilized. The vendor was contacted early regarding this disclosure.
