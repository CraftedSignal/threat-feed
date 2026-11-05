---
brief_id: brief-2026-11-05-cendio-thinlinc-auth-bypass
event_id: brief-2026-11-05-cendio-thinlinc-auth-bypass
revision: 2
activity_at: "2026-11-05T16:33:05Z"
revision_history:
  - revision: 2
    at: "2026-11-05T16:33:05Z"
    checksum: sha256:07b0ed63febf9de7546a9e33c62e4a98b848fe375a7c4cde6e6f23bb52959ad2
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-119744&utm_source=rss&utm_medium=rss
title: 'Cendio ThinLinc: Improper authentication in web client (CVE-2026-119744)'
slug: 2026-11-cendio-thinlinc-auth-bypass
description: Cendio ThinLinc versions 4.1.0 through 4.20.0 contain an improper authentication vulnerability in the browser-based web client (tlwebaccess) that allows an authenticated attacker to impersonate other users, including root.
date: "2026-11-05T16:21:01Z"
lastmod: "2026-11-05T16:32:11Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:cendio:thinlinc:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-119744&utm_source=rss&utm_medium=rss
vendors:
  - Cendio
products:
  - ThinLinc (4.1.0 through 4.20.0)
cves:
  - id: CVE-2026-119744
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119744
  - https://sploitus.com/exploit?id=CVE-2026-119744&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-05T16:32:11Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-119744&utm_source=rss&utm_medium=rss
---

Cendio ThinLinc versions 4.1.0 through 4.20.0 contain an improper authentication vulnerability in its browser-based web client (tlwebaccess). An authenticated attacker can impersonate any other user, including root, by exploiting flaws in multi-step authentication flows such as one-time passwords, login banners, or expired password prompts.
