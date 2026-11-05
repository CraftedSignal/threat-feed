---
brief_id: brief-2026-11-05-vitafit-auth-bypass
event_id: brief-2026-11-05-vitafit-auth-bypass
revision: 2
activity_at: "2026-11-05T00:22:30Z"
revision_history:
  - revision: 2
    at: "2026-11-05T00:22:30Z"
    checksum: sha256:b2ad67a1450022b7b89faa12157de7ae17313890c32461ab2ff0b0fbbd81ced5
    summary: poc_available
    changed_fields:
      - affected_vendors
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-54384&utm_source=rss&utm_medium=rss
title: 'VitaFit cloud API: Authentication bypass (CVE-2026-54384)'
slug: 2026-11-vitafit-auth-bypass
description: VitaFit cloud API before 2026-10-30 contained an authentication bypass vulnerability allowing remote attackers to obtain a full session for a victim's account by submitting a linked Google or Facebook account identifier to the POST /front/login/sns/ endpoint without providing proof of ownership.
date: "2026-11-05T00:05:58Z"
lastmod: "2026-11-05T00:20:58Z"
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
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-54384&utm_source=rss&utm_medium=rss
vendors:
  - VitaFit
cves:
  - id: CVE-2026-54384
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54384
  - https://sploitus.com/exploit?id=CVE-2026-54384&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-05T00:20:58Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-54384&utm_source=rss&utm_medium=rss
---

VitaFit cloud API before 2026-10-30 contained an authentication bypass vulnerability. Remote attackers can obtain a full session for a victim's account by submitting a linked Google or Facebook account identifier to the POST /front/login/sns/ endpoint without providing proof of ownership from the identity provider. Attackers can forge a login to read and modify the victim's profile and delete the account's authentication record, preventing the legitimate user from logging in.
