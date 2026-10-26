---
brief_id: brief-2026-10-26-oray-x5-pro-crlf
event_id: brief-2026-10-26-oray-x5-pro-crlf
revision: 2
activity_at: "2026-10-26T11:42:37Z"
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
title: 'Oray Pugongying X5 Pro: CRLF injection in Ser2net (CVE-2026-116231)'
slug: 2026-10-oray-x5-pro-crlf
description: A security flaw in the Ser2net component of Oray Pugongying X5 Pro 7.6.1 allows for remote CRLF injection via manipulation of the regmsg argument.
date: "2026-10-26T09:40:17Z"
lastmod: "2026-10-26T11:41:33Z"
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
  - cpe:2.3:a:oray:pugongying_x5_pro:*:*:*:*:*:*:*:*
  - cpe:2.3:a:oray:pugongying_x5_pro:7.6.1:*:*:*:*:*:*:*
vendors:
  - Oray
products:
  - Oray Pugongying X5 Pro 7.6.1
  - Pugongying X5 Pro (7.6.1)
cves:
  - id: CVE-2026-116231
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-116233
    cvss: 9.1
    kev_status: "false"
  - id: CVE-2026-116234
    cvss: 9.1
    kev_status: "false"
  - id: CVE-2026-116232
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116231
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116233
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116234
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116232
updates:
  - at: "2026-10-26T09:40:34Z"
    level: L2
    summary: added CVE-2026-116233, CVE-2026-116234
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116233
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116234
  - at: "2026-10-26T11:41:33Z"
    level: L2
    summary: added CVE-2026-116232
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116232
---

A security flaw has been identified in the Ser2net component of Oray Pugongying X5 Pro 7.6.1. Manipulation of the 'regmsg' argument results in CRLF injection. The attack can be initiated remotely. Public exploit code is available for this vulnerability. The vendor was contacted but did not respond.
